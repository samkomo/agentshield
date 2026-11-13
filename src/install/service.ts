/**
 * Keeping the gateway running: a per-user launchd agent on macOS, a systemd
 * user unit on Linux. Per-user on purpose — no sudo, and the service runs as
 * the account that owns the keys.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export interface ServiceSpec {
  /** The AgentShield checkout or package root. */
  root: string;
  /** The gateway data directory. */
  dir: string;
  host: string;
  port: number;
}

export interface ServiceState { supported: boolean; installed: boolean; running: boolean; path: string; detail: string }

const label = (): string => process.env.AGENTSHIELD_SERVICE_LABEL ?? 'com.agentshield.gateway';
const unitName = (): string => `${process.env.AGENTSHIELD_SERVICE_LABEL ?? 'agentshield'}.service`;

const plistPath = (): string => join(homedir(), 'Library', 'LaunchAgents', `${label()}.plist`);
const unitPath = (): string => join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'systemd', 'user', unitName());

const run = (cmd: string, args: string[]): { ok: boolean; out: string } => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return { ok: !r.error && r.status === 0, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim() };
};

const xml = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const programArgs = (spec: ServiceSpec): string[] => [
  process.execPath, join(spec.root, 'bin', 'agentshield.mjs'), 'serve', '--dir', spec.dir, '--host', spec.host, '--port', String(spec.port),
];

export function launchdPlist(spec: ServiceSpec): string {
  const log = join(spec.dir, 'gateway.log');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${xml(label())}</string>
  <key>ProgramArguments</key>
  <array>
${programArgs(spec).map((a) => `    <string>${xml(a)}</string>`).join('\n')}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>WorkingDirectory</key><string>${xml(spec.dir)}</string>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
</dict>
</plist>
`;
}

export function systemdUnit(spec: ServiceSpec): string {
  const quoted = programArgs(spec).map((a) => `"${a.replace(/(["\\])/g, '\\$1')}"`).join(' ');
  return `[Unit]
Description=AgentShield gateway
After=network.target

[Service]
ExecStart=${quoted}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`;
}

const launchdDomains = (): string[] => {
  const uid = process.getuid!();
  return [`gui/${uid}`, `user/${uid}`];
};

export function serviceState(): ServiceState {
  if (process.platform === 'darwin') {
    const path = plistPath();
    const running = launchdDomains().some((d) => /state = running/.test(run('launchctl', ['print', `${d}/${label()}`]).out));
    return { supported: true, installed: existsSync(path), running, path, detail: `launchd agent ${label()}` };
  }
  if (process.platform === 'linux') {
    const path = unitPath();
    return { supported: true, installed: existsSync(path), running: run('systemctl', ['--user', 'is-active', unitName()]).out === 'active', path, detail: `systemd user unit ${unitName()}` };
  }
  return { supported: false, installed: false, running: false, path: '', detail: `no service support on ${process.platform}; run "agentshield up" under your own supervisor` };
}

/** Writes the service definition and starts it, replacing one that is already there. */
export function installService(spec: ServiceSpec): ServiceState {
  if (process.platform === 'darwin') {
    const path = plistPath();
    mkdirSync(dirname(path), { recursive: true });
    for (const d of launchdDomains()) run('launchctl', ['bootout', `${d}/${label()}`]);
    writeFileSync(path, launchdPlist(spec), { mode: 0o644 });
    let last = '';
    for (const d of launchdDomains()) {
      const r = run('launchctl', ['bootstrap', d, path]);
      if (r.ok) return serviceState();
      last = r.out;
    }
    throw new Error(`launchd would not load ${path}: ${last}`);
  }
  if (process.platform === 'linux') {
    const path = unitPath();
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, systemdUnit(spec), { mode: 0o644 });
    const reload = run('systemctl', ['--user', 'daemon-reload']);
    if (!reload.ok) throw new Error(`systemctl --user is not available here: ${reload.out}`);
    const enable = run('systemctl', ['--user', 'enable', '--now', unitName()]);
    if (!enable.ok) throw new Error(`systemd would not start ${unitName()}: ${enable.out}`);
    run('systemctl', ['--user', 'restart', unitName()]);
    return serviceState();
  }
  throw new Error(serviceState().detail);
}

export function uninstallService(): boolean {
  const before = serviceState();
  if (!before.supported || !before.installed) return false;
  if (process.platform === 'darwin') for (const d of launchdDomains()) run('launchctl', ['bootout', `${d}/${label()}`]);
  else {
    run('systemctl', ['--user', 'disable', '--now', unitName()]);
    run('systemctl', ['--user', 'daemon-reload']);
  }
  rmSync(before.path, { force: true });
  return true;
}
