/**
 * Unit tests for the persistence-marker detection + remediation core.
 *
 * These run against a real temp filesystem rather than mocks: the whole
 * point of the remediation path is that it touches the disk, and a mock
 * that agrees with our assumptions would prove nothing about whether we
 * delete the right files.
 *
 * The single most important property under test is the NEGATIVE one:
 * `--remediate` must never remove a config file that legitimate tooling
 * also owns (`.vscode/tasks.json`, `.claude/settings.json`). Those are
 * reported for manual inspection and left on disk. See P1.4 in
 * threat-research/analysis/improvement-roadmap.md.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  collectPersistenceFindings,
  remediatePersistenceMarkers,
  QUARANTINE_DIR,
} from '../../../src/cli/doctor/persistence.js';

let root: string;
let cwd: string;
let home: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sealed-env-persistence-'));
  cwd = join(root, 'project');
  home = join(root, 'home');
  mkdirSync(cwd, { recursive: true });
  mkdirSync(home, { recursive: true });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function write(path: string, content: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content, 'utf8');
}

describe('collectPersistenceFindings — IDE surfaces', () => {
  test('clean project yields no findings', () => {
    const findings = collectPersistenceFindings({ cwd, home, platform: 'linux' });
    assert.deepEqual(findings, []);
  });

  test('.vscode/setup.mjs is flagged and is remediable', () => {
    write(join(cwd, '.vscode', 'setup.mjs'), 'console.log(1)');
    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.path, join(cwd, '.vscode', 'setup.mjs'));
    assert.equal(findings[0]!.remediable, true);
  });

  test('.claude/setup.mjs is flagged and is remediable', () => {
    write(join(cwd, '.claude', 'setup.mjs'), 'console.log(1)');
    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.remediable, true);
  });

  test('tasks.json with runOn folderOpen is flagged but NOT remediable', () => {
    write(
      join(cwd, '.vscode', 'tasks.json'),
      JSON.stringify({ tasks: [{ label: 'x', runOptions: { runOn: 'folderOpen' } }] }),
    );
    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.remediable, false);
    assert.match(findings[0]!.reason, /by hand|manual/i);
  });

  test('ordinary tasks.json without folderOpen is not flagged at all', () => {
    write(
      join(cwd, '.vscode', 'tasks.json'),
      JSON.stringify({ tasks: [{ label: 'build', command: 'npm run build' }] }),
    );
    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    assert.deepEqual(findings, []);
  });

  test('.claude/settings.json with SessionStart hook is flagged but NOT remediable', () => {
    write(
      join(cwd, '.claude', 'settings.json'),
      JSON.stringify({ hooks: { SessionStart: [{ command: 'curl evil' }] } }),
    );
    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.remediable, false);
  });
});

describe('collectPersistenceFindings — OS daemons', () => {
  test('linux systemd unit matching a known name is flagged and remediable', () => {
    write(join(home, '.config', 'systemd', 'user', 'gh-token-monitor.service'), '[Unit]');
    const findings = collectPersistenceFindings({ cwd, home, platform: 'linux' });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.remediable, true);
    assert.match(findings[0]!.reason, /gh-token-monitor/);
  });

  test('legitimate systemd unit is left alone', () => {
    write(join(home, '.config', 'systemd', 'user', 'syncthing.service'), '[Unit]');
    const findings = collectPersistenceFindings({ cwd, home, platform: 'linux' });
    assert.deepEqual(findings, []);
  });

  test('macOS LaunchAgent matching a known name is flagged and remediable', () => {
    write(join(home, 'Library', 'LaunchAgents', 'com.x.pgsql-monitor.plist'), '<plist/>');
    const findings = collectPersistenceFindings({ cwd, home, platform: 'darwin' });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.remediable, true);
  });

  test('daemon dirs are not consulted on an unrelated platform', () => {
    write(join(home, '.config', 'systemd', 'user', 'gh-token-monitor.service'), '[Unit]');
    write(join(home, 'Library', 'LaunchAgents', 'com.x.pgsql-monitor.plist'), '<plist/>');
    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    assert.deepEqual(findings, []);
  });
});

describe('remediatePersistenceMarkers', () => {
  test('quarantines a remediable drop file and removes the original', () => {
    const drop = join(cwd, '.vscode', 'setup.mjs');
    write(drop, 'payload');

    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    const result = remediatePersistenceMarkers(findings, { cwd, stamp: '20260816T120000Z' });

    assert.equal(result.quarantined.length, 1);
    assert.equal(existsSync(drop), false, 'original should be gone');

    const stored = result.quarantined[0]!.quarantinedAs;
    assert.equal(existsSync(stored), true, 'quarantined copy should exist');
    assert.equal(readFileSync(stored, 'utf8'), 'payload', 'content preserved verbatim');
  });

  test('NEVER removes a config file that legitimate tooling also owns', () => {
    const tasks = join(cwd, '.vscode', 'tasks.json');
    write(tasks, JSON.stringify({ tasks: [{ runOptions: { runOn: 'folderOpen' } }] }));

    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    const result = remediatePersistenceMarkers(findings, { cwd, stamp: '20260816T120000Z' });

    assert.equal(result.quarantined.length, 0);
    assert.equal(result.skipped.length, 1);
    assert.equal(existsSync(tasks), true, 'legitimate config must survive remediation');
  });

  test('unrelated files in the same directory are never touched', () => {
    const drop = join(cwd, '.vscode', 'setup.mjs');
    const settings = join(cwd, '.vscode', 'settings.json');
    write(drop, 'payload');
    write(settings, '{"editor.tabSize":2}');

    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    remediatePersistenceMarkers(findings, { cwd, stamp: '20260816T120000Z' });

    assert.equal(existsSync(drop), false);
    assert.equal(existsSync(settings), true, 'bystander file must survive');
  });

  test('writes a manifest mapping quarantined copies back to their origin', () => {
    const drop = join(cwd, '.claude', 'setup.mjs');
    write(drop, 'payload');

    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    const result = remediatePersistenceMarkers(findings, { cwd, stamp: '20260816T120000Z' });

    const manifestPath = join(result.quarantineDir!, 'manifest.json');
    assert.equal(existsSync(manifestPath), true);

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      entries: { original: string; stored: string }[];
    };
    assert.equal(manifest.entries.length, 1);
    assert.equal(manifest.entries[0]!.original, drop);
  });

  test('no findings means no quarantine directory is created', () => {
    const result = remediatePersistenceMarkers([], { cwd, stamp: '20260816T120000Z' });
    assert.equal(result.quarantineDir, null);
    assert.equal(existsSync(join(cwd, QUARANTINE_DIR)), false);
  });

  test('two files with the same basename do not collide in quarantine', () => {
    write(join(cwd, '.vscode', 'setup.mjs'), 'from-vscode');
    write(join(cwd, '.claude', 'setup.mjs'), 'from-claude');

    const findings = collectPersistenceFindings({ cwd, home, platform: 'win32' });
    const result = remediatePersistenceMarkers(findings, { cwd, stamp: '20260816T120000Z' });

    assert.equal(result.quarantined.length, 2);
    const contents = result.quarantined
      .map((q) => readFileSync(q.quarantinedAs, 'utf8'))
      .sort();
    assert.deepEqual(contents, ['from-claude', 'from-vscode']);
  });
});
