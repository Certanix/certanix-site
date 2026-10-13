#!/usr/bin/env bash
# Put the PUBLIC certanix-verify wheel, and asn1crypto 1.5.1 (its one pure-Python
# dependency that Pyodide does not ship), into verify/runtime/verifier/, with the
# licence files the page links to.
#
# The wheel is the public release artifact, built outside any repository by the
# certanix-verify release preparation. This script refuses a wheel that is not a public
# build: a version with a local suffix (anything after a "+"), or a licence other than
# BSD-3-Clause-Clear.
#
# Usage: tools/build-verifier.sh /path/to/certanix_verify-X.Y.Z-py3-none-any.whl
set -euo pipefail

WHEEL="${1:?path to the public certanix_verify wheel}"
ASN1_WHEEL="asn1crypto-1.5.1-py2.py3-none-any.whl"
ASN1_SHA256="db4e40728b728508912cbb3d44f19ce188f218e9eba635821bb4b68564f8fd67"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/verify/runtime/verifier"
LICENCE="$ROOT/verify/licence"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 -m pip -q download --no-deps "asn1crypto==1.5.1" -d "$WORK"

rm -rf "$DEST" "$LICENCE" && mkdir -p "$DEST" "$LICENCE"
cp "$WHEEL" "$WORK/$ASN1_WHEEL" "$DEST/"
python3 - "$DEST" "$LICENCE" "$(basename "$WHEEL")" "$ASN1_WHEEL" "$ASN1_SHA256" <<'PY'
import base64, hashlib, json, re, sys, zipfile
dest, licence, verifier, asn1, asn1_sha = sys.argv[1:]
def sha(path):
    return hashlib.sha256(open(path, "rb").read()).digest()
if sha(f"{dest}/{asn1}").hex() != asn1_sha:
    sys.exit(f"{asn1}: sha256 is not the pinned one")
with zipfile.ZipFile(f"{dest}/{verifier}") as w:
    [meta] = [n for n in w.namelist() if n.endswith(".dist-info/METADATA")]
    metadata = w.read(meta).decode()
    version = re.search(r"^Version: (.+)$", metadata, re.M).group(1).strip()
    if "+" in version:
        sys.exit(f"refusing {verifier}: version {version} is not a public build")
    if "License-Expression: BSD-3-Clause-Clear" not in metadata:
        sys.exit(f"refusing {verifier}: not licensed BSD-3-Clause-Clear")
    # The licence files the page links to: exactly those inside the wheel.
    for name in ("LICENSE", "NOTICE", "PATENTS-NOTICE.md"):
        data = w.read(f"{meta.rsplit('/', 1)[0]}/licenses/{name}")
        open(f"{licence}/{name if name != 'PATENTS-NOTICE.md' else name}", "wb").write(data)
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
bundle = {"certanix_verify_version": version, "wheels": wheels}
json.dump(bundle, open(f"{dest}/bundle.json", "w"), indent=2)
open(f"{dest}/bundle.json", "a").write("\n")
print(json.dumps(bundle, indent=2))
PY
