/**
 * ASCII art for the `sealed-env hunt-shai-hulud` command.
 *
 * Three states map to three drawings:
 *
 *   CLEAN      — the desert is calm; no Shai-Hulud has been found
 *                in the dep tree. A small, distant worm shape.
 *
 *   SUSPECT    — partial findings; suspicious patterns but no
 *                confirmed compromise. A rising worm with mouth
 *                closed.
 *
 *   COMPROMISED — confirmed match against known-malicious package
 *                versions or active persistence markers. A wide-
 *                mouth maw rising to consume your repo.
 *
 * Art kept deliberately minimal — Dune sandworm iconography is
 * vertical, maw-up, with rings. We're not winning ASCII contests;
 * we're making `hunt-shai-hulud` memorable.
 *
 * Lyric reference (the chant from Children of Dune):
 *   "Shai-Hulud, the maker, has come."
 * Used here only in the COMPROMISED state — it's a warning, not
 * decoration.
 */

export const SANDWORM_CLEAN = String.raw`
                      ___
                    .'   '.
                   /  ___  \
                  |  |   |  |
                   \  '-'  /
                    '.___.'

         the desert is calm. no maker rises today.
`;

export const SANDWORM_SUSPECT = String.raw`
                ___
             ,-' . '-.
            /  /===\  \
           |  ((   ))  |
            \  \===/  /
             '-.___.-'
            /         \
           |  /\ /\ /\ |
           |  \/ \/ \/ |
            \         /
             '-------'

       something stirs beneath the sand.
`;

export const SANDWORM_COMPROMISED = String.raw`
              ___________________
             /                   \
            |   ___   ___   ___   |
            |  /   \ /   \ /   \  |
            | |  o  |  o  |  o  | |
            |  \___/ \___/ \___/  |
             \                   /
              \  /\  /\  /\  /\ /
               \/  \/  \/  \/  \/
              /   /   /   /   /
             /   /   /   /   /
            |   |   |   |   |
            |   |   |   |   |
            |   |   |   |   |
            |   |   |   |   |
             \___ ___ ___ ___/

          Shai-Hulud, the maker, has come.

  the IOCs below match published research. isolate
  the host BEFORE revoking any credentials — see
  docs/incident-response.md for the deadman switch
  warning and the correct order of operations.
`;
