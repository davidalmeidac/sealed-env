/**
 * Cross-platform OS keychain backend.
 *
 * Stores `SEALED_ENV_*` values in the operator's OS-native secret
 * store, which gives us:
 *   - Encrypted at rest (locked to the user's login session)
 *   - Excluded from cloud backups (Time Machine, OneDrive, iCloud)
 *   - Inaccessible to other users on the same machine
 *
 * We shell out to platform-native CLIs instead of bundling a native
 * Node module like `keytar` — that keeps `sealed-env`'s install size
 * tiny, removes the cross-compile burden, and matches our "core has
 * zero third-party imports" property.
 *
 * Per-platform mapping of `SEALED_ENV_*` → keychain entry:
 *
 *   Windows  → `cmdkey` for credential names "sealed-env-<lowercase>"
 *              (pure cmd.exe, ships with every Windows since XP)
 *   macOS    → `security` for service "sealed-env", account "<name>"
 *   Linux    → `secret-tool` (libsecret) for attribute service=sealed-env
 *
 * If the platform CLI is missing or fails, we return `null` from
 * `tryRead*` and surface a clear error from `write*`/`delete*`. The
 * caller can decide whether to fall back to `.env.local` or refuse.
 */

import { spawnSync } from 'node:child_process';

/** Names we manage. Anything else is left alone. */
export const KEYCHAIN_NAMES = [
  'SEALED_ENV_KEY',
  'SEALED_ENV_SIGNING_KEY',
  'SEALED_ENV_TOTP_SECRET',
] as const;

export type KeychainName = (typeof KEYCHAIN_NAMES)[number];

export interface KeychainBackend {
  /** Human-readable name of the backend (e.g. "Windows Credential Manager"). */
  readonly label: string;
  /** Whether the backend's CLI is available on this machine. */
  isAvailable(): boolean;
  /** Read a secret. Returns `null` if it's not stored. */
  read(name: KeychainName): string | null;
  /** Store/overwrite a secret. */
  write(name: KeychainName, value: string): void;
  /** Remove a secret if present. No-op if it's not there. */
  remove(name: KeychainName): void;
}

/**
 * Pick the right backend for this OS. Returns `null` on platforms
 * we don't support yet, in which case the caller should fall back
 * to file-based storage.
 */
export function detectBackend(): KeychainBackend | null {
  if (process.platform === 'win32') return new WindowsBackend();
  if (process.platform === 'darwin') return new MacOSBackend();
  if (process.platform === 'linux') return new LinuxBackend();
  return null;
}

// ── Windows: DPAPI via PowerShell ───────────────────────────────
//
// We encrypt the secret with DPAPI (`ProtectedData.Protect`) using the
// current user's login key, then write the ciphertext to a file under
// %LOCALAPPDATA%\sealed-env\. Only the same Windows user, on the same
// machine, can decrypt — and the DPAPI master key is NOT included in
// most cloud backup tooling (Time Machine equivalents on Windows like
// File History, OneDrive, Backblaze).
//
// We deliberately avoid `cmdkey` because its companion read API
// (CredRead via Win32 advapi32) requires P/Invoke wrappers, which
// makes the PowerShell snippet long and brittle. DPAPI is just five
// lines and uses only `System.Security`, which ships with every .NET
// install on Windows.
class WindowsBackend implements KeychainBackend {
  readonly label = 'Windows DPAPI (per-user)';

  isAvailable(): boolean {
    return commandExists('powershell');
  }

  read(name: KeychainName): string | null {
    const filePath = this.fileFor(name);
    const ps = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
try {
  $bytes = [System.IO.File]::ReadAllBytes('${filePath}')
  $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'CurrentUser')
  [System.Console]::Out.Write([System.Text.Encoding]::UTF8.GetString($plain))
} catch { exit 1 }
`;
    const result = spawnSync(
      'powershell',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { encoding: 'utf8' },
    );
    if (result.status !== 0) return null;
    return result.stdout || null;
  }

  write(name: KeychainName, value: string): void {
    const filePath = this.fileFor(name);
    const dir = filePath.substring(0, filePath.lastIndexOf('\\'));
    // PowerShell here-string with single quotes preserves the value
    // without expansion. We URL-escape the value's quote chars
    // defensively even though hex/base64/base32 don't contain them.
    const escapedValue = value.replace(/'/g, "''");
    const ps = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
New-Item -ItemType Directory -Force -Path '${dir}' | Out-Null
$bytes = [System.Text.Encoding]::UTF8.GetBytes('${escapedValue}')
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
[System.IO.File]::WriteAllBytes('${filePath}', $encrypted)
`;
    const result = spawnSync(
      'powershell',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8' },
    );
    if (result.status !== 0) {
      throw new Error(
        `DPAPI write failed: ${result.stderr || 'unknown'}`,
      );
    }
  }

  remove(name: KeychainName): void {
    const filePath = this.fileFor(name);
    spawnSync(
      'powershell',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `Remove-Item -Path '${filePath}' -ErrorAction SilentlyContinue`,
      ],
      { stdio: 'ignore' },
    );
  }

  private fileFor(name: KeychainName): string {
    const localAppData = process.env['LOCALAPPDATA'] || `${process.env['USERPROFILE']}\\AppData\\Local`;
    const slug = name.toLowerCase().replace(/_/g, '-');
    return `${localAppData}\\sealed-env\\${slug}.bin`;
  }
}

// ── macOS: security ─────────────────────────────────────────────
class MacOSBackend implements KeychainBackend {
  readonly label = 'macOS Keychain';

  isAvailable(): boolean {
    return commandExists('security');
  }

  read(name: KeychainName): string | null {
    const result = spawnSync(
      'security',
      ['find-generic-password', '-s', 'sealed-env', '-a', name, '-w'],
      { encoding: 'utf8' },
    );
    if (result.status !== 0) return null;
    return result.stdout.trim() || null;
  }

  write(name: KeychainName, value: string): void {
    // -U updates if exists; -s service, -a account, -w password
    const result = spawnSync(
      'security',
      ['add-generic-password', '-U', '-s', 'sealed-env', '-a', name, '-w', value],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    if (result.status !== 0) {
      throw new Error(
        `security add-generic-password failed: ${result.stderr?.toString() || 'unknown'}`,
      );
    }
  }

  remove(name: KeychainName): void {
    spawnSync(
      'security',
      ['delete-generic-password', '-s', 'sealed-env', '-a', name],
      { stdio: 'ignore' },
    );
    // Same as Windows: ignore "not found" exit codes.
  }
}

// ── Linux: secret-tool (libsecret) ──────────────────────────────
class LinuxBackend implements KeychainBackend {
  readonly label = 'libsecret (GNOME Keyring / KWallet)';

  isAvailable(): boolean {
    return commandExists('secret-tool');
  }

  read(name: KeychainName): string | null {
    const result = spawnSync(
      'secret-tool',
      ['lookup', 'service', 'sealed-env', 'name', name],
      { encoding: 'utf8' },
    );
    if (result.status !== 0) return null;
    return result.stdout.trim() || null;
  }

  write(name: KeychainName, value: string): void {
    // secret-tool reads the secret value from stdin to avoid leaking
    // it via the process command line / `ps`.
    const result = spawnSync(
      'secret-tool',
      ['store', '--label', `sealed-env ${name}`, 'service', 'sealed-env', 'name', name],
      {
        input: value,
        stdio: ['pipe', 'ignore', 'pipe'],
        encoding: 'utf8',
      },
    );
    if (result.status !== 0) {
      throw new Error(
        `secret-tool store failed: ${result.stderr?.toString() || 'unknown'}`,
      );
    }
  }

  remove(name: KeychainName): void {
    spawnSync('secret-tool', ['clear', 'service', 'sealed-env', 'name', name], {
      stdio: 'ignore',
    });
  }
}

function commandExists(cmd: string): boolean {
  const probe = process.platform === 'win32' ? 'where' : 'which';
  const result = spawnSync(probe, [cmd], { stdio: 'ignore' });
  return result.status === 0;
}
