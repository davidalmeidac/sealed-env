#!/usr/bin/env bash
# Demonstrates cross-stack interop: seal a file with Node, decrypt with Java.
# This is the headline feature of sealed-env — a file written by either
# implementation works on the other without conversion.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p out

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
note()  { printf '\033[36m›\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m!\033[0m %s\n' "$*"; }
hr()    { printf '\033[90m─%.0s\033[0m' {1..72}; printf '\n'; }

CLI="node ../node/dist/cli/index.js"

# Java classpath separator differs by platform: ; on Windows (Git Bash, MSYS,
# Cygwin) and : everywhere else.
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) CP=';' ;;
    *) CP=':' ;;
esac

bold "[ Cross-stack ] Seal in Node, decrypt with Java"
hr

# ── 1. Java prerequisite check
if ! command -v java >/dev/null 2>&1; then
  warn "Java not in PATH. This script requires JDK 17+ to demonstrate the Java side."
  echo "    Install JDK 17 or later, then re-run."
  exit 0
fi
JAVA_VERSION=$(java -version 2>&1 | head -1)
ok "Java available: $JAVA_VERSION"

# to_native: convert Unix-style path to native (Windows uses backslash form
# when invoking native binaries like java/javac under Git Bash).
to_native() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) cygpath -w "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}

JAR_PATTERN="../java/sealed-env-core/target/sealed-env-core-*.jar"
JAR_UNIX=$(ls $JAR_PATTERN 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
if [ -z "$JAR_UNIX" ]; then
  warn "Java jar not built. Building now (this takes 30-60s on first run)..."
  ( cd ../java && mvn -B -ntp -pl sealed-env-core -am install -DskipTests )
  JAR_UNIX=$(ls $JAR_PATTERN 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
fi
if [ -z "$JAR_UNIX" ]; then
  printf '\033[31m✗\033[0m Could not find or build sealed-env-core jar.\n'
  exit 1
fi
JAR=$(to_native "$JAR_UNIX")
ok "Java jar: $JAR_UNIX"

# Find Bouncy Castle (transitive dep of sealed-env-core, needed for Argon2id and scrypt)
BC_JAR_UNIX=$(find ~/.m2/repository/org/bouncycastle -name "bcprov-jdk18on-*.jar" 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
if [ -z "$BC_JAR_UNIX" ]; then
  warn "Bouncy Castle jar not found in ~/.m2 — running 'mvn install' would fetch it."
  exit 1
fi
BC_JAR=$(to_native "$BC_JAR_UNIX")
ok "Bouncy Castle: $(basename "$BC_JAR_UNIX")"

# ── 2. Seal the file with Node CLI in basic mode
hr
note "Sealing out/.env with Node (mode=basic)..."
MASTER_KEY=$(openssl rand -hex 32)
SEALED_ENV_KEY=$MASTER_KEY $CLI encrypt out/.env --out out/crossstack.sealed --mode basic
ok "Sealed file: out/crossstack.sealed"
note "Note the KDF= line — Node honestly declares 'scrypt' (Node stdlib has no Argon2id):"
sed -n '2,3p' out/crossstack.sealed | sed 's/^/    /'

# ── 3. Tiny Java program that reads the file and prints decrypted plaintext
hr
note "Writing a small Java program that imports sealed-env-core and decrypts..."
mkdir -p out/java-demo
cat > out/java-demo/CrossStackDemo.java <<'JAVA'
import io.github.davidalmeidac.sealedenv.SealedEnv;
import io.github.davidalmeidac.sealedenv.format.SealedFileParser;
import io.github.davidalmeidac.sealedenv.core.SealedFile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

public class CrossStackDemo {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: CrossStackDemo <sealed-file> <master-key-hex>");
            System.exit(2);
        }
        String text = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        SealedFile file = SealedFileParser.parse(text);

        System.out.println("[Java] Parsed file:");
        System.out.println("[Java]   mode = " + file.mode());
        System.out.println("[Java]   kdf  = " + file.kdf() + " (written by Node, read by Java)");

        SealedEnv.UnsealOptions opts = new SealedEnv.UnsealOptions();
        opts.file = file;
        opts.masterKey = HexFormat.of().parseHex(args[1]);

        byte[] plaintext = SealedEnv.unseal(opts);
        System.out.println("[Java] Decrypted plaintext:");
        System.out.println("------------------------------------------------------------");
        System.out.print(new String(plaintext, StandardCharsets.UTF_8));
        System.out.println("------------------------------------------------------------");
    }
}
JAVA

# ── 4. Compile + run
hr
note "Compiling Java demo..."
DEMO_DIR_NATIVE=$(to_native "$(pwd)/out/java-demo")
javac -cp "${JAR}${CP}${BC_JAR}" -d out/java-demo out/java-demo/CrossStackDemo.java
ok "Compiled."

note "Running Java with the file Node just sealed..."
echo
java -cp "${DEMO_DIR_NATIVE}${CP}${JAR}${CP}${BC_JAR}" CrossStackDemo \
  out/crossstack.sealed "$MASTER_KEY"
echo

hr
echo
bold "Cross-stack roundtrip complete."
echo "  • Node CLI wrote the file (KDF=scrypt)"
echo "  • Java sealed-env-core read the file and decrypted byte-identical"
echo "  • Same wire format, no conversion, no shared library — only the spec"
echo
echo "This is the same flow tested automatically in CI on every commit."
echo "See: java/sealed-env-core/src/test/java/.../CrossStackInteropTest.java"
