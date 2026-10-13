#!/usr/bin/env bash
# Build the verifier bundle /verify runs: the certanix-verify wheel, built from a COMMITTED
# ref of a certanix-beta checkout (never a working tree), and asn1crypto 1.5.1, its one
# pure-Python dependency that Pyodide does not ship. Writes verify/runtime/verifier/.
#
# verify/runtime/verifier/ is GITIGNORED on purpose. The internal certanix-verify build
# contains modules that are not yet cleared for publication. The bundle is built locally
# to test the page; what goes live is decided by Axel, and only from a build cleared for
# release. See verify/README.md.
#
# Usage: tools/build-verifier.sh /path/to/certanix-beta [REF]      (REF defaults to main)
set -euo pipefail

BETA="${1:?path to a certanix-beta checkout}"
REF="${2:-main}"
ASN1_WHEEL="asn1crypto-1.5.1-py2.py3-none-any.whl"
ASN1_SHA256="db4e40728b728508912cbb3d44f19ce188f218e9eba635821bb4b68564f8fd67"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/verify/runtime/verifier"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

commit="$(git -C "$BETA" rev-parse "$REF^{commit}")"
git -C "$BETA" archive "$commit" packages/certanix-verify | tar -x -C "$WORK"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" -q install hatchling
"$WORK/venv/bin/pip" -q wheel --no-deps --no-build-isolation \
  "$WORK/packages/certanix-verify" -w "$WORK/dist"
"$WORK/venv/bin/pip" -q download --no-deps "asn1crypto==1.5.1" -d "$WORK/dist"

rm -rf "$DEST" && mkdir -p "$DEST"
cp "$WORK"/dist/*.whl "$DEST/"
python3 - "$DEST" "$commit" "$ASN1_WHEEL" "$ASN1_SHA256" <<'PY'
import base64, glob, hashlib, json, os, sys
dest, commit, asn1, asn1_sha = sys.argv[1:]
def sha(path):
    return hashlib.sha256(open(path, "rb").read()).digest()
if sha(f"{dest}/{asn1}").hex() != asn1_sha:
    sys.exit(f"{asn1}: sha256 is not the pinned one")
[verifier] = [os.path.basename(p) for p in glob.glob(f"{dest}/certanix_verify-*.whl")]
wheels = []
for name in (verifier, asn1):
    digest = sha(f"{dest}/{name}")
    wheels.append({
        "file": name,
        "sha256": digest.hex(),
        # Subresource Integrity: the page fetches each wheel with this value, so a wheel
        # that is not this one is refused by the browser before Python sees it.
        "integrity": "sha256-" + base64.b64encode(digest).decode(),
    })
bundle = {
    "certanix_verify_version": verifier.split("-")[1],
    "built_from_commit": commit,
    "wheels": wheels,
}
json.dump(bundle, open(f"{dest}/bundle.json", "w"), indent=2)
print(json.dumps(bundle, indent=2))
PY
