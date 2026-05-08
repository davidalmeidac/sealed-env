/**
 * Unit tests for the SSH transport layer used by `deploy --remote`.
 *
 * Covers the pure functions: parseSshTarget, shellEscape, buildRemoteScript.
 * Live SSH (validateSshConnection, execOverSsh) is integration-tested
 * separately against a real sshd in CI.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildRemoteScript,
  parseSshTarget,
  shellEscape,
} from '../../src/cli/utils/ssh.js';

describe('parseSshTarget', () => {
  test('parses user@host', () => {
    const r = parseSshTarget('alice@example.com');
    assert.equal(r.user, 'alice');
    assert.equal(r.host, 'example.com');
  });

  test('parses user@ip', () => {
    const r = parseSshTarget('ops@10.0.0.5');
    assert.equal(r.user, 'ops');
    assert.equal(r.host, '10.0.0.5');
  });

  test('handles user with dot', () => {
    const r = parseSshTarget('john.doe@host');
    assert.equal(r.user, 'john.doe');
    assert.equal(r.host, 'host');
  });

  test('uses last @ if multiple (rare but defined)', () => {
    // matrix-style usernames sometimes contain @
    const r = parseSshTarget('user@matrix.org@host.example');
    assert.equal(r.user, 'user@matrix.org');
    assert.equal(r.host, 'host.example');
  });

  test('rejects missing @', () => {
    assert.throws(() => parseSshTarget('justhost'), /must be in user@host/);
  });

  test('rejects leading @', () => {
    assert.throws(() => parseSshTarget('@host'), /must be in user@host/);
  });

  test('rejects trailing @', () => {
    assert.throws(() => parseSshTarget('user@'), /must be in user@host/);
  });

  test('trims whitespace', () => {
    const r = parseSshTarget('  alice@host  ');
    assert.equal(r.user, 'alice');
    assert.equal(r.host, 'host');
  });
});

describe('shellEscape', () => {
  test('simple value wraps in single quotes', () => {
    assert.equal(shellEscape('hello'), "'hello'");
  });

  test('empty string', () => {
    assert.equal(shellEscape(''), "''");
  });

  test('escapes embedded single quote', () => {
    // The classic sequence: close quote, escaped literal quote, reopen.
    assert.equal(shellEscape("it's mine"), "'it'\\''s mine'");
  });

  test('multiple single quotes', () => {
    assert.equal(shellEscape("a'b'c"), "'a'\\''b'\\''c'");
  });

  test('does NOT expand $ inside single quotes', () => {
    // Single quotes prevent any expansion — the literal $HOME is preserved.
    assert.equal(shellEscape('$HOME'), "'$HOME'");
  });

  test('does NOT expand backticks', () => {
    assert.equal(shellEscape('`whoami`'), "'`whoami`'");
  });

  test('preserves newlines literally', () => {
    assert.equal(shellEscape('line1\nline2'), "'line1\nline2'");
  });

  test('preserves unicode', () => {
    assert.equal(shellEscape('héllo·世界'), "'héllo·世界'");
  });

  test('preserves backslashes (no extra escaping needed in single quotes)', () => {
    assert.equal(shellEscape('a\\b\\c'), "'a\\b\\c'");
  });
});

describe('buildRemoteScript', () => {
  test('emits sorted exports + exec', () => {
    const env = new Map([
      ['ZULU', '1'],
      ['ALPHA', '2'],
      ['MIKE', '3'],
    ]);
    const script = buildRemoteScript(env, ['./up.sh']);
    assert.equal(
      script,
      "export ALPHA='2'\nexport MIKE='3'\nexport ZULU='1'\nexec './up.sh'\n",
    );
  });

  test('multi-arg command is space-separated and quoted', () => {
    const env = new Map([['X', 'y']]);
    const script = buildRemoteScript(env, ['docker', 'compose', 'up', '-d']);
    assert.equal(
      script,
      "export X='y'\nexec 'docker' 'compose' 'up' '-d'\n",
    );
  });

  test('quotes special characters in env values', () => {
    const env = new Map([
      ['DATABASE_URL', 'postgres://user:p@ss@db/'],
      ['SECRET', "it's secret"],
      ['WEIRD', '$HOME `whoami`'],
    ]);
    const script = buildRemoteScript(env, ['app']);
    // sorted: DATABASE_URL, SECRET, WEIRD
    assert.equal(
      script,
      "export DATABASE_URL='postgres://user:p@ss@db/'\n" +
        "export SECRET='it'\\''s secret'\n" +
        "export WEIRD='$HOME `whoami`'\n" +
        "exec 'app'\n",
    );
  });

  test('empty env still emits exec', () => {
    const script = buildRemoteScript(new Map(), ['ls', '-la']);
    assert.equal(script, "exec 'ls' '-la'\n");
  });

  test('throws if command empty', () => {
    assert.throws(
      () => buildRemoteScript(new Map([['X', '1']]), []),
      /no command provided/,
    );
  });

  test('output is deterministic across runs (cross-stack vector basis)', () => {
    const env = new Map([
      ['B', '2'],
      ['A', '1'],
      ['C', '3'],
    ]);
    const a = buildRemoteScript(env, ['./run.sh']);
    const b = buildRemoteScript(env, ['./run.sh']);
    assert.equal(a, b);
  });

  test('values containing commands are NOT executed (single-quoted)', () => {
    const env = new Map([['EVIL', "'; rm -rf / #"]]);
    const script = buildRemoteScript(env, ['echo']);
    // The semicolon and rm are inside the quoted value.
    assert.equal(
      script,
      "export EVIL=''\\''; rm -rf / #'\nexec 'echo'\n",
    );
    // The shell interprets this as: EVIL='; rm -rf / #
    // — a literal value, not a command sequence. Verified by the
    // structure: no unquoted ; or rm.
    assert.match(script, /^export EVIL='/);
  });
});
