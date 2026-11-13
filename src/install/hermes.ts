/**
 * Installing into a Hermes agent runtime.
 *
 * Nothing here guesses where Hermes lives. Every location is asked of the
 * `hermes` command itself (`config path`, `config env-path`, `plugins list
 * --json`), because the home directory depends on `HERMES_HOME`, on profiles
 * and on a sticky active profile. The plugin is installed by Hermes's own
 * installer, pinned to the commit of this checkout, so Hermes's source scan,
 * version gate and install record all apply.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const PLUGIN_NAME = 'agentshield';
export const PLUGIN_SUBDIR = 'integrations/hermes/agentshield';
/** The oldest Hermes the plugin has been run against. Also stated in plugin.yaml, where Hermes enforces it. */
export const MIN_HERMES = '0.22.0';

export interface HermesInfo {
  /** The command and leading arguments that address this Hermes home, e.g. ["hermes", "-p", "work"]. */
  command: string[];
  version: string;
  home: string;
  configPath: string;
  envPath: string;
  plugin: { status: string; version: string; source: string } | null;
}

export type PluginSource =
  | { kind: 'git'; url: string; sha: string }
  | { kind: 'copy'; path: string; why: string };

export class InstallError extends Error {}

function capture(command: string[], args: string[]): { ok: boolean; out: string; err: string; missing: boolean } {
  const r = spawnSync(command[0]!, [...command.slice(1), ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000 });
  const missing = (r.error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';
  return { ok: !r.error && r.status === 0, out: r.stdout ?? '', err: r.stderr ?? '', missing };
}

/** Runs a Hermes command with the terminal attached, so its own warnings and prompts reach the person installing. */
function attached(command: string[], args: string[]): boolean {
  const r = spawnSync(command[0]!, [...command.slice(1), ...args], { stdio: 'inherit', timeout: 300_000 });
  return !r.error && r.status === 0;
}

const lastLine = (text: string): string => text.split('\n').map((l) => l.trim()).filter(Boolean).pop() ?? '';

const versionTuple = (v: string): number[] => v.split('.').slice(0, 3).map((n) => Number.parseInt(n, 10) || 0);

export function versionAtLeast(version: string, minimum: string): boolean {
  const a = versionTuple(version);
  const b = versionTuple(minimum);
  for (let i = 0; i < 3; i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  return true;
}

function readPlugin(command: string[]): HermesInfo['plugin'] {
  const listed = capture(command, ['plugins', 'list', '--json', '--user']);
  const start = listed.out.indexOf('[');
  const end = listed.out.lastIndexOf(']');
  if (!listed.ok || start < 0 || end < start) throw new InstallError(`"${command.join(' ')} plugins list --json" did not return a list: ${lastLine(listed.err || listed.out)}`);
  const entries = JSON.parse(listed.out.slice(start, end + 1)) as { name: string; status: string; version?: string; source?: string }[];
  const found = entries.find((e) => e.name === PLUGIN_NAME);
  return found ? { status: found.status, version: found.version ?? '', source: found.source ?? '' } : null;
}

/** Asks Hermes what it is and where it keeps things. Throws, with what to do, if there is no Hermes to ask. */
export function detectHermes(opts: { bin?: string; profile?: string } = {}): HermesInfo {
  const bin = opts.bin ?? process.env.AGENTSHIELD_HERMES_BIN ?? 'hermes';
  const command = opts.profile ? [bin, '-p', opts.profile] : [bin];
  const ver = capture([bin], ['--version']);
  if (ver.missing) {
    throw new InstallError(`Hermes was not found ("${bin}" is not on PATH). Install Hermes first, run this in the account that runs it, or pass --hermes /path/to/hermes.`);
  }
  const version = /v?(\d+\.\d+\.\d+)/.exec(ver.out)?.[1];
  if (!ver.ok || !version) throw new InstallError(`"${bin} --version" did not report a version: ${lastLine(ver.err || ver.out)}`);
  const cfg = capture(command, ['config', 'path']);
  const configPath = lastLine(cfg.out);
  if (!cfg.ok || !configPath.startsWith('/')) throw new InstallError(`"${command.join(' ')} config path" did not report a location: ${lastLine(cfg.err || cfg.out)}`);
  const env = capture(command, ['config', 'env-path']);
  const envPath = env.ok && lastLine(env.out).startsWith('/') ? lastLine(env.out) : join(dirname(configPath), '.env');
  return { command, version, home: dirname(configPath), configPath, envPath, plugin: readPlugin(command) };
}

function git(root: string, args: string[]): { ok: boolean; out: string } {
  const r = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return { ok: !r.error && r.status === 0, out: (r.stdout ?? '').trim() };
}

/**
 * Where the plugin comes from. A clean Git checkout is installed by commit, so
 * what Hermes runs is exactly what this gateway shipped with. Anything else
 * (a packaged build, or a checkout with uncommitted plugin edits) is copied.
 */
export function pluginSource(root: string): PluginSource {
  const path = join(root, PLUGIN_SUBDIR);
  const top = git(root, ['rev-parse', '--show-toplevel']);
  if (!top.ok || realpathSync(top.out) !== realpathSync(root)) return { kind: 'copy', path, why: 'this AgentShield is not a Git checkout' };
  const head = git(root, ['rev-parse', 'HEAD']);
  if (!head.ok || !git(root, ['cat-file', '-e', `HEAD:${PLUGIN_SUBDIR}/plugin.yaml`]).ok) return { kind: 'copy', path, why: 'the plugin is not committed in this checkout' };
  if (git(root, ['status', '--porcelain', '--', PLUGIN_SUBDIR]).out) return { kind: 'copy', path, why: 'the plugin has uncommitted changes in this checkout' };
  return { kind: 'git', url: `file://${realpathSync(root)}`, sha: head.out };
}

export function pluginCurrent(info: HermesInfo, source: PluginSource): boolean {
  return source.kind === 'git' && info.plugin?.status === 'enabled' && info.plugin.source.includes(`pinned@${source.sha.slice(0, 8)}`);
}

/** Installs or replaces the plugin and makes sure it is enabled. Returns the state Hermes reports afterwards. */
export function installPlugin(info: HermesInfo, source: PluginSource): HermesInfo['plugin'] {
  if (source.kind === 'git') {
    const args = ['plugins', 'install', `${source.url}#${PLUGIN_SUBDIR}`, '--ref', source.sha, '--enable'];
    if (info.plugin) args.push('--force');
    if (!attached(info.command, args)) throw new InstallError('Hermes refused to install the plugin; its own message is above.');
  } else {
    const target = join(info.home, 'plugins', PLUGIN_NAME);
    rmSync(target, { recursive: true, force: true });
    mkdirSync(dirname(target), { recursive: true });
    cpSync(source.path, target, { recursive: true, filter: (src) => !src.includes('__pycache__') });
  }
  // A replacement keeps whatever enabled/disabled choice was there before, and a copied plugin starts not enabled.
  if (readPlugin(info.command)?.status !== 'enabled' && !attached(info.command, ['plugins', 'enable', PLUGIN_NAME])) {
    throw new InstallError('Hermes refused to enable the plugin; its own message is above.');
  }
  const after = readPlugin(info.command);
  if (after?.status !== 'enabled') throw new InstallError(`After installing, Hermes reports the plugin as "${after?.status ?? 'missing'}", not enabled.`);
  return after;
}

export function removePlugin(info: HermesInfo): boolean {
  if (!info.plugin) return false;
  if (!attached(info.command, ['plugins', 'remove', PLUGIN_NAME])) throw new InstallError('Hermes refused to remove the plugin; its own message is above.');
  return true;
}

/** Where the plugin looks for the agent's credential. */
export function tokenPath(): string {
  return process.env.AGENTSHIELD_TOKEN_FILE ?? join(homedir(), '.config', 'agentshield', 'token');
}

export function writeToken(token: string): string {
  const path = tokenPath();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${token.trim()}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

export function tokenState(): { path: string; exists: boolean; ownerOnly: boolean } {
  const path = tokenPath();
  if (!existsSync(path)) return { path, exists: false, ownerOnly: false };
  return { path, exists: true, ownerOnly: (statSync(path).mode & 0o077) === 0 };
}

export const DEFAULT_URL = 'http://127.0.0.1:8787';

const envLine = (key: string): RegExp => new RegExp(`^\\s*${key}\\s*=`);

function readEnv(envPath: string, key: string): string | undefined {
  if (!existsSync(envPath)) return undefined;
  const line = readFileSync(envPath, 'utf8').split('\n').filter((l) => envLine(key).test(l)).pop();
  return line?.slice(line.indexOf('=') + 1).trim().replace(/^["']|["']$/g, '');
}

/** Sets or removes one of the plugin's own settings in Hermes's env file. No other line is touched. */
function writeEnv(envPath: string, key: string, value: string | undefined): boolean {
  if (readEnv(envPath, key) === value) return false;
  const kept = existsSync(envPath) ? readFileSync(envPath, 'utf8').split('\n').filter((l) => !envLine(key).test(l)) : [];
  while (kept.length && kept[kept.length - 1] === '') kept.pop();
  if (value !== undefined) kept.push(`${key}=${value}`);
  writeFileSync(envPath, kept.length ? `${kept.join('\n')}\n` : '', { mode: 0o600 });
  return true;
}

export function readMode(envPath: string): 'enforce' | 'monitor' {
  return readEnv(envPath, 'AGENTSHIELD_MODE')?.toLowerCase() === 'monitor' ? 'monitor' : 'enforce';
}

/** Enforce is the plugin's default, so it is stored as no line at all. */
export function writeMode(envPath: string, mode: 'enforce' | 'monitor'): boolean {
  return writeEnv(envPath, 'AGENTSHIELD_MODE', mode === 'monitor' ? 'monitor' : undefined);
}

/** The gateway address the plugin will use: the default unless Hermes's env file says otherwise. */
export function readUrl(envPath: string): string {
  return (readEnv(envPath, 'AGENTSHIELD_URL') ?? DEFAULT_URL).replace(/\/$/, '');
}

export function writeUrl(envPath: string, url: string | undefined): boolean {
  return writeEnv(envPath, 'AGENTSHIELD_URL', url === undefined || url === DEFAULT_URL ? undefined : url);
}

export interface Probe { ok: boolean; detail: string }

/** One retry: a connection kept open from an earlier request may have been closed by the gateway in the meantime. */
async function request(url: string, init: RequestInit, timeoutMs: number): Promise<Response | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await fetch(url, { ...init, headers: { ...(init.headers as Record<string, string> | undefined), connection: 'close' }, signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      // fall through to the retry, then to "not answering"
    }
  }
  return null;
}

export async function gatewayHealth(url: string): Promise<Probe> {
  const res = await request(`${url}/healthz`, {}, 5000);
  if (!res) return { ok: false, detail: `nothing is answering at ${url}` };
  return res.ok ? { ok: true, detail: `answering at ${url}` } : { ok: false, detail: `${url} answered ${res.status}` };
}

/** Sends one read-only question through the same route the plugin uses, with the agent's credential. Nothing is recorded. */
export async function hookSelfTest(url: string, token: string, tool = 'hermes'): Promise<Probe> {
  const res = await request(`${url}/v1/hook/${encodeURIComponent(tool)}/before`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ tool_name: 'read_file', args: { path: 'agentshield-selftest.txt' }, task_id: 'agentshield-selftest', dry_run: true }),
  }, 10_000);
  if (!res) return { ok: false, detail: `nothing is answering at ${url}` };
  const body = (await res.json().catch(() => ({}))) as { action?: string; reason?: string; error?: { code?: string; message?: string } };
  if (res.status === 401) return { ok: false, detail: 'the gateway does not recognise this credential' };
  if (!res.ok) return { ok: false, detail: `the gateway answered ${res.status}${body.error?.code ? ` (${body.error.code})` : ''}` };
  if (body.action === 'allow') return { ok: true, detail: 'a test read was checked and allowed' };
  return { ok: false, detail: `a harmless test read came back "${body.action}"${body.reason ? `: ${body.reason}` : ''}` };
}
