# sealed-env · brand assets

The visual identity of `sealed-env` is a **Roman sigillum** — a wax impression
made by a signet ring. Romans used these to authenticate documents and prove
they had not been tampered with: exactly what `sealed-env` does in code.

## Files

| File | Use case | Notes |
|---|---|---|
| [`logo-lockup.svg`](./logo-lockup.svg) | Hero / README header / social cards | Sigillum + wordmark + tagline |
| [`logo-sigillum.svg`](./logo-sigillum.svg) | Standalone seal — print, posters, large icons | Includes the curved Latin legend |
| [`logo-sigillum-mono.svg`](./logo-sigillum-mono.svg) | Favicon, npm avatar, GitHub org icon | Stripped down — readable at 16px |
| [`logo-type.svg`](./logo-type.svg) | Wordmark only — footers, signatures | When the sigillum doesn't fit |

## The system

**Color palette** (only three):

| | Hex | Role |
|---|---|---|
| Sealing wax red | `#A8201A` | The wax — historical Roman seal red |
| Cream paper | `#f1ebe0` | The pressed-on field |
| Deep ink | `#1a1612` | Type, engraved rules |

**Typography:**
- Sigillum monogram + legend: **Cinzel** (lapidary Roman caps in the Trajan tradition)
- Wordmark: **Fraunces** italic (editorial serif with humanist roots)
- Tagline / metadata: **JetBrains Mono** (technical, calm)

**Anti-AI principles applied** (no, really):

- ❌ No radial gradients
- ❌ No glossy highlights
- ❌ No fake scalloped petals around the rim
- ❌ No drop shadows
- ❌ No padlock or generic crypto iconography
- ✓ Flat fills only
- ✓ Hand-irregular wax disk perimeter (intentional asymmetry)
- ✓ Subtle paper grain via `<feTurbulence>`
- ✓ Authentic Roman orthography (`CVSTOS · ARCANI`, V for U)
- ✓ Olive sprigs flanking the monogram (Roman peace + permanence symbol)

## Latin motto

The seal carries the legend:

> **`SEALED · ENV · CVSTOS · ARCANI · MMXXVI`**

`CVSTOS ARCANI` is Latin for *"Guardian of the secret"* — which is, almost
word-for-word, what the library does. `MMXXVI` is the year 2026 in Roman
numerals, marking the year of first release.

## Usage in your projects

If you're building tooling around `sealed-env` and want to use the mark:

- The MIT license covers the code, **not** the mark itself
- Use the mark to refer to the project (compatibility, integration, plugins)
- Don't modify the mark or use it to imply official endorsement
- For derivative works that need their own visual identity, derive don't copy

Questions about brand usage: [davidalmeidac@proton.me](mailto:davidalmeidac@proton.me)

## Credits

Designed by [David Almeida](https://github.com/davidalmeidac) for
[`sealed-env`](https://github.com/davidalmeidac/sealed-env).

Inspired by Roman administrative practice — specifically, the
[*sigillum*](https://en.wikipedia.org/wiki/Seal_%28emblem%29#Roman_sigillum)
used to authenticate official correspondence in the Empire and beyond,
through the Middle Ages.
