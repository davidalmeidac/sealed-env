/**
 * Minimal flag parser. We avoid `commander`/`yargs` to keep the zero-deps
 * promise. Supports:
 *
 *   --flag value
 *   --flag=value
 *   --bool-flag       (sets to true)
 *   positional args   (returned in `positional`)
 *
 * Unknown flags throw.
 */

export interface FlagSpec {
  type: 'string' | 'boolean';
  default?: string | boolean;
}

export interface ParsedFlags {
  values: Record<string, string | boolean>;
  positional: string[];
}

export function parseFlags(
  argv: string[],
  spec: Record<string, FlagSpec>,
): ParsedFlags {
  const values: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (const [name, s] of Object.entries(spec)) {
    if (s.default !== undefined) {
      values[name] = s.default;
    }
  }

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    let key: string;
    let valueFromInline: string | undefined;
    if (eq > 0) {
      key = token.substring(2, eq);
      valueFromInline = token.substring(eq + 1);
    } else {
      key = token.substring(2);
    }

    const flag = spec[key];
    if (!flag) {
      throw new Error(`unknown flag: --${key}`);
    }

    if (flag.type === 'boolean') {
      values[key] = valueFromInline === undefined
        ? true
        : valueFromInline.toLowerCase() === 'true';
      continue;
    }

    if (valueFromInline !== undefined) {
      values[key] = valueFromInline;
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new Error(`flag --${key} expects a value`);
      }
      values[key] = next;
      i++;
    }
  }

  return { values, positional };
}
