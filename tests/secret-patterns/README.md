# Secret-pattern test corpus

This directory validates the regex patterns documented in
[`../../SECRET-PATTERNS.md`](../../SECRET-PATTERNS.md) and bundled at
[`../../.gitleaks/sealed-env.toml`](../../.gitleaks/sealed-env.toml).

## Layout

```
positive/   ← every match here is expected (100% recall required)
negative/   ← no match here is allowed (100% precision required)
```

## Running the validation

Two ways:

### 1. With gitleaks (recommended — exercises the real production path)

```bash
# Install gitleaks (https://github.com/gitleaks/gitleaks)

# Positive: should report findings in every line of every file
gitleaks detect \
  --config=.gitleaks/sealed-env.toml \
  --no-git \
  --source=tests/secret-patterns/positive/ \
  --verbose

# Negative: should report ZERO findings
gitleaks detect \
  --config=.gitleaks/sealed-env.toml \
  --no-git \
  --source=tests/secret-patterns/negative/ \
  --verbose
```

The CI workflow `.github/workflows/secret-patterns.yml` runs both
checks on every push and fails if recall < 100% or precision < 100%.

### 2. With the bundled validator (no external tools)

```bash
node scripts/validate-secret-patterns.mjs
```

Walks the corpus, applies the same regex set, and prints a pass/fail
summary. Useful for fast local iteration when you're tweaking a pattern.

## Adding new test cases

When you find a real-world leak that the patterns missed, add the
literal string (redacted as needed) to the `positive/` corpus and
commit. CI will fail until the pattern catches it.

When a false positive is reported in the wild, add the offending string
to the `negative/` corpus and tighten the regex until both corpora pass.

This is the same discipline used by `gitleaks` itself, `trufflehog`,
and the GitHub Secret Scanning Partner Program.
