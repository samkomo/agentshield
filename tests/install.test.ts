/**
 * The install path a stranger follows: install.sh, then `connect`, `doctor`,
 * `disconnect`. Hermes is a stub here so the suite runs anywhere; the same
 * path is run by hand against a real Hermes before a release.
 */
import assert from 'node:assert/strict';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { launchdPlist, systemdUnit } from '../src/install/service.ts';
import { pluginSource, versionAtLeast } from '../src/install/hermes.ts';

const ROOT = join(import.meta.dirname, '..');
const exec = promisify(execFile);
const STUB = join(ROOT, 'tests', 'fixtures', 'hermes-stub.sh');

const freePort = (): Promise<number> => new Promise((done) => {
  const s = createServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address() as { port: number };
    s.close(() => done(port));
  });
});

/** The working tree as a committed Git repository, standing in for the published one. */
async function snapshot(into: string): Promise<string> {
  const files = (await exec('git', ['-C', ROOT, 'ls-files', '-co', '--exclude-standard'])).stdout.split('\n').filter(Boolean);
  for (const f of files) {
    if (!existsSync(join(ROOT, f))) continue;
    mkdirSync(dirname(join(into, f)), { recursive: true });
    cpSync(join(ROOT, f), join(into, f));
  }
  const git = (...args: string[]) => exec('git', ['-C', into, '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', ...args]);
  await git('init', '--quiet', '-b', 'main');
  await git('add', '-A');
  await git('commit', '--quiet', '-m', 'snapshot');
  return into;
}

const fails = async (p: Promise<unknown>): Promise<{ stdout: string; stderr: string; code: number }> => {
  try {
    await p;
  } catch (err) {
    return err as { stdout: string; stderr: string; code: number };
  }
  throw new Error('expected the command to fail');
};

test('install.sh: installs from Git into the home directory, verifies, updates in place, refuses to clobber, uninstalls', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'agentshield-install-'));
  try {
    const origin = await snapshot(join(tmp, 'origin'));
    const home = join(tmp, 'home');
    mkdirSync(home);
    const env = { PATH: process.env.PATH, HOME: home, AGENTSHIELD_REPO_URL: `file://${origin}` } as NodeJS.ProcessEnv;
    const install = (...args: string[]) => exec('bash', [join(origin, 'install.sh'), ...args], { env });
    const launcher = join(home, '.local', 'bin', 'agentshield');

    const first = await install();
    assert.match(first.stdout, /Installed agentshield \d+\.\d+\.\d+ \([0-9a-f]{7,}\)/);
    assert.match(first.stdout, /is not on your PATH/, 'says how to reach the command rather than editing shell files');
    assert.ok(existsSync(join(home, '.local', 'share', 'agentshield', 'src', 'cli.ts')));
    assert.match((await exec(launcher, ['--version'], { env })).stdout, /^agentshield \d/);
    assert.ok(!existsSync(join(home, '.zshrc')) && !existsSync(join(home, '.bashrc')) && !existsSync(join(home, '.agentshield')), 'touches nothing but its two folders');

    assert.match((await install()).stdout, /^Updating /, 'a second run updates the same checkout');

    writeFileSync(join(home, '.local', 'share', 'agentshield', 'README.md'), 'edited');
    assert.match((await fails(install())).stderr, /has local changes/);
    await exec('git', ['-C', join(home, '.local', 'share', 'agentshield'), 'checkout', '--', 'README.md']);

    assert.match((await fails(install('--ref', 'no-such-ref'))).stderr, /could not find 'no-such-ref'/);
    assert.match((await fails(exec('bash', [join(origin, 'install.sh')], { env: { ...env, PATH: '/usr/bin:/bin' } }))).stderr, /Node\.js 24 or later is required/);

    mkdirSync(join(home, '.agentshield'));
    assert.match((await install('--uninstall')).stdout, /data .* was not touched/);
    assert.ok(!existsSync(launcher) && !existsSync(join(home, '.local', 'share', 'agentshield')) && existsSync(join(home, '.agentshield')));

    writeFileSync(launcher, '#!/bin/sh\necho someone else\n', { mode: 0o755 });
    assert.match((await fails(install())).stderr, /was not written by this installer/);
    assert.equal(readFileSync(launcher, 'utf8'), '#!/bin/sh\necho someone else\n');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('connect hermes: asks Hermes where it lives, refuses without a gateway, installs through Hermes, verifies, and undoes cleanly', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'agentshield-connect-'));
  const dir = join(tmp, 'data');
  const hermesHome = join(tmp, 'hermes', 'profiles', 'work');
  const tokenFile = join(tmp, 'agent-home', '.config', 'agentshield', 'token');
  const port = await freePort();
  const env = { ...process.env, HOME: join(tmp, 'home'), STUB_HERMES_HOME: hermesHome, AGENTSHIELD_TOKEN_FILE: tokenFile, AGENTSHIELD_HOME: dir } as NodeJS.ProcessEnv;
  delete env.AGENTSHIELD_URL;
  const cli = (args: string[], extra: NodeJS.ProcessEnv = {}) => exec(process.execPath, [join(ROOT, 'src/cli.ts'), ...args, '--hermes', STUB], { env: { ...env, ...extra } });
  const calls = (): string => (existsSync(join(hermesHome, 'calls.log')) ? readFileSync(join(hermesHome, 'calls.log'), 'utf8') : '');
  let gateway: ChildProcess | undefined;
  try {
    await exec(process.execPath, [join(ROOT, 'src/cli.ts'), 'init'], { env });

    // No gateway yet: the plan is shown, and nothing in Hermes or on the gateway is touched.
    const early = await fails(cli(['connect', 'hermes', '--port', String(port)]));
    assert.match(early.stdout, /Found Hermes 0\.22\.7/);
    assert.match(early.stdout, /profile "work"/);
    assert.match(early.stderr, /The gateway is not running .* Nothing was changed\./);
    assert.ok(!existsSync(tokenFile) && !existsSync(join(dir, 'agents')) && !/plugins (install|enable)/.test(calls()));

    gateway = spawn(process.execPath, [join(ROOT, 'src/cli.ts'), 'serve', '--port', String(port)], { env, stdio: 'ignore' });
    for (let i = 0; i < 50; i++) {
      if (await fetch(`http://127.0.0.1:${port}/healthz`).then((r) => r.ok, () => false)) break;
      await new Promise((r) => setTimeout(r, 100));
    }

    const old = await fails(cli(['connect', 'hermes', '--port', String(port)], { STUB_HERMES_VERSION: '0.19.2' }));
    assert.match(old.stderr, /needs Hermes 0\.22\.0 or later; this is 0\.19\.2/);

    const dry = await cli(['connect', 'hermes', '--port', String(port), '--dry-run']);
    assert.match(dry.stdout, /Dry run: nothing was changed\./);
    assert.ok(!existsSync(tokenFile) && !existsSync(join(hermesHome, 'plugins')));

    const done = await cli(['connect', 'hermes', '--port', String(port)]);
    assert.match(done.stdout, /created agent "work"/, 'the agent is named after the Hermes profile');
    assert.match(done.stdout, /Connected\. Hermes 0\.22\.7 at .*profiles\/work/);
    assert.match(done.stdout, /a test read was checked and allowed/);
    const token = readFileSync(tokenFile, 'utf8').trim();
    assert.ok(token.startsWith('as_') && !done.stdout.includes(token) && !done.stderr.includes(token), 'the credential is never displayed');
    assert.equal(statSync(tokenFile).mode & 0o077, 0);
    assert.ok(existsSync(join(hermesHome, 'plugins', 'agentshield', 'plugin.yaml')), 'the plugin is in the home Hermes reported, not a guessed one');
    assert.equal(readFileSync(join(hermesHome, '.env'), 'utf8'), `AGENTSHIELD_URL=http://127.0.0.1:${port}\n`, 'a non-default gateway address is recorded for the plugin');
    const source = pluginSource(ROOT);
    assert.match(calls(), source.kind === 'git' ? new RegExp(`plugins install file://.*#integrations/hermes/agentshield --ref ${source.sha} --enable`) : /plugins enable agentshield/);

    // Existing lines in Hermes's env file survive a mode change, and enforce is stored as no line.
    writeFileSync(join(hermesHome, '.env'), `OTHER=1\nAGENTSHIELD_URL=http://127.0.0.1:${port}\n`);
    assert.match((await cli(['connect', 'hermes', '--mode', 'monitor'])).stdout, /mode:\s+monitor/);
    assert.equal(readFileSync(join(hermesHome, '.env'), 'utf8'), `OTHER=1\nAGENTSHIELD_URL=http://127.0.0.1:${port}\nAGENTSHIELD_MODE=monitor\n`);
    const again = await cli(['connect', 'hermes', '--mode', 'enforce']);
    assert.ok(!again.stdout.includes('Gateway: '), 'a repeat run changes nothing on the gateway');
    assert.equal(readFileSync(tokenFile, 'utf8').trim(), token);
    assert.equal(readFileSync(join(hermesHome, '.env'), 'utf8'), `OTHER=1\nAGENTSHIELD_URL=http://127.0.0.1:${port}\n`);

    const healthy = JSON.parse((await cli(['doctor', '--json'])).stdout) as { ok: boolean; checks: { name: string; status: string }[] };
    assert.equal(healthy.ok, true);
    assert.deepEqual(healthy.checks.filter((c) => ['Gateway', 'Hermes plugin', 'Credential', 'Test call', 'Mode', 'Agent "work"'].includes(c.name)).map((c) => c.status), ['ok', 'ok', 'ok', 'ok', 'ok', 'ok']);

    // The two-account split: the gateway account enrolls, the agent account connects with the credential on stdin.
    const enrolled = await cli(['enroll', 'hermes', '--agent', 'elsewhere']);
    assert.match(enrolled.stdout, /agentshield connect hermes --token-stdin < .*agents\/elsewhere\.token/);
    const elsewhere = readFileSync(join(dir, 'agents', 'elsewhere.token'), 'utf8').trim();
    assert.ok(!enrolled.stdout.includes(elsewhere));
    assert.match((await cli(['enroll', 'hermes', '--agent', 'elsewhere'])).stdout, /nothing to change/);
    const remote = await cli(['connect', 'hermes', '--token-file', join(dir, 'agents', 'elsewhere.token')], { AGENTSHIELD_HOME: join(tmp, 'no-gateway-data-here') });
    assert.match(remote.stdout, /use the credential supplied/);
    assert.equal(readFileSync(tokenFile, 'utf8').trim(), elsewhere);
    writeFileSync(join(tmp, 'bad'), 'as_0000000000000000000000000000\n');
    assert.match((await fails(cli(['connect', 'hermes', '--token-file', join(tmp, 'bad')]))).stderr, /does not recognise this credential\. Hermes was not changed/);
    assert.equal(readFileSync(tokenFile, 'utf8').trim(), elsewhere, 'a rejected credential replaces nothing');

    // A plugin Hermes has switched off is a failure, with the command that fixes it.
    writeFileSync(join(hermesHome, '.status'), 'disabled');
    const broken = await fails(cli(['doctor']));
    assert.match(broken.stdout, /FAIL\s+Hermes plugin\s+disabled.*NOT being checked/);
    assert.match(broken.stdout, /fix: agentshield connect hermes/);
    await cli(['connect', 'hermes']);
    assert.equal(readFileSync(join(hermesHome, '.status'), 'utf8').trim(), 'enabled');

    const gone = await cli(['disconnect', 'hermes']);
    assert.match(gone.stdout, /removed the plugin/);
    assert.ok(!existsSync(tokenFile) && !existsSync(join(hermesHome, 'plugins', 'agentshield')));
    assert.equal(readFileSync(join(hermesHome, '.env'), 'utf8'), 'OTHER=1\n');
    assert.match((await exec(process.execPath, [join(ROOT, 'src/cli.ts'), 'audit', 'verify'], { env })).stdout, /Chain intact/);
  } finally {
    // The gateway writes a checkpoint as it stops; wait for it before removing its folder.
    if (gateway && gateway.exitCode === null) {
      const exited = new Promise((r) => gateway!.once('exit', r));
      gateway.kill();
      await exited;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('connect hermes: says what to do when Hermes is not installed', async () => {
  const err = await fails(exec(process.execPath, [join(ROOT, 'src/cli.ts'), 'connect', 'hermes', '--hermes', '/nonexistent/hermes']));
  assert.match(err.stderr, /Hermes was not found/);
});

test('service definitions: launchd and systemd units run the gateway from this checkout as the current user', () => {
  const spec = { root: '/opt/agent shield', dir: '/home/u/.agentshield', host: '127.0.0.1', port: 8787 };
  const plist = launchdPlist(spec);
  assert.match(plist, /<key>RunAtLoad<\/key><true\/>/);
  assert.match(plist, /<key>KeepAlive<\/key><dict><key>SuccessfulExit<\/key><false\/><\/dict>/);
  assert.ok(plist.includes('<string>/opt/agent shield/bin/agentshield.mjs</string>') && plist.includes('<string>serve</string>'));
  assert.ok(!/UserName|sudo/.test(plist));
  const unit = systemdUnit(spec);
  assert.match(unit, /ExecStart="[^"]+" "\/opt\/agent shield\/bin\/agentshield\.mjs" "serve" "--dir" "\/home\/u\/\.agentshield"/);
  assert.match(unit, /WantedBy=default\.target/);
  assert.ok(versionAtLeast('0.22.7', '0.22.0') && versionAtLeast('1.0.0', '0.22.0') && !versionAtLeast('0.21.9', '0.22.0'));
});
