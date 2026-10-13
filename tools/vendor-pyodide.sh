#!/usr/bin/env bash
# Vendor the Pyodide runtime that /verify runs certanix-verify in, from the npm release
# tarball, checked against the registry's sha512 before anything is copied.
#
# Only the files the verifier needs are kept: the interpreter, the standard library, the
# package lock, and the four wheels `cryptography` resolves to in that lock (cffi,
# cryptography, pycparser, six), each checked against the lock's sha256. Nothing is
# fetched by the page from anywhere but this site.
#
# Usage: tools/vendor-pyodide.sh            (re-vendors the pinned version)
set -euo pipefail

VERSION="314.0.7"
NPM_SHA512="0YvXxEhfEdpLfb/XkM2BFAeMROq0iMUX2bzzH9pOttyMcWkwq+HbE5uyuGD82LN7y2q+SNvi/6V5JEsOlD2R1A=="
WHEELS=(
  "cffi-2.0.0-cp314-cp314-pyemscripten_2026_0_wasm32.whl"
  "cryptography-47.0.0-cp314-abi3-pyemscripten_2026_0_wasm32.whl"
  "pycparser-3.0-py3-none-any.whl"
  "six-1.17.0-py2.py3-none-any.whl"
)
CORE=(pyodide.mjs pyodide.asm.mjs pyodide.asm.wasm python_stdlib.zip pyodide-lock.json)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/verify/runtime/pyodide"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -sfL "https://registry.npmjs.org/pyodide/-/pyodide-${VERSION}.tgz" -o "$WORK/p.tgz"
got="$(openssl dgst -sha512 -binary "$WORK/p.tgz" | base64)"
[ "$got" = "$NPM_SHA512" ] || { echo "npm tarball sha512 mismatch: $got" >&2; exit 1; }
tar xzf "$WORK/p.tgz" -C "$WORK"

rm -rf "$DEST" && mkdir -p "$DEST"
for f in "${CORE[@]}"; do cp "$WORK/package/$f" "$DEST/"; done
cp "$WORK/package/README.md" "$DEST/PYODIDE-README.md"

for w in "${WHEELS[@]}"; do
  curl -sfL "https://cdn.jsdelivr.net/pyodide/v${VERSION}/full/$w" -o "$DEST/$w"
done
python3 - "$DEST" "${WHEELS[@]}" <<'PY'
import hashlib, json, sys
dest, wheels = sys.argv[1], sys.argv[2:]
lock = json.load(open(f"{dest}/pyodide-lock.json"))
want = {p["file_name"]: p["sha256"] for p in lock["packages"].values()}
for w in wheels:
    got = hashlib.sha256(open(f"{dest}/{w}", "rb").read()).hexdigest()
    if got != want[w]:
        sys.exit(f"{w}: sha256 {got} is not the lock's {want[w]}")
print(f"pyodide {lock['info']['python']} vendored; {len(wheels)} wheels match the lock")
PY
