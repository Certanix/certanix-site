# certanix.eu/verify

A page that explains what verifying a Certanix evidence pack proves, gives the
command-line steps, publishes the signing key, and verifies a pack in the browser.

**Status: live at https://certanix.eu/verify/ from 2026-10-13, on Axel's go.** Every
change to this page, its wheel or its sample is again Axel's decision before it is pushed.

## Files

| Path | What it is |
|---|---|
| `index.html` | The page. Its content security policy is in a `<meta>` tag (GitHub Pages cannot set headers). |
| `verify.css` | The site's identity, in a file of its own: the policy allows no inline style. |
| `app.mjs` | The page around the verifier: loads it, closes the network, checks the lock, handles files. |
| `engine.mjs` | Loads Pyodide and the verifier wheel; `runCli(argv, files)` calls `certanix_verify.cli.main`. No verification logic in JavaScript. |
| `keys/certanix-hsm.pub` | The HSM public key. SHA-256 of its DER SPKI: `5849077784fa60616ea83e8bff35c8b294e17631a42435cd20192dd09d9f9ae5`. |
| `runtime/pyodide/` | Pyodide 314.0.7 (CPython 3.14.2), vendored by `tools/vendor-pyodide.sh`, checked against the npm sha512 and the lock's sha256 for each wheel. MPL-2.0. |
| `runtime/verifier/` | The PUBLIC certanix-verify wheel (0.16.0, BSD-3-Clause-Clear) and asn1crypto 1.5.1, placed by `tools/build-verifier.sh`, which refuses a wheel with a local version suffix or another licence. Fetched by the page with Subresource Integrity. |
| `licence/` | LICENSE, NOTICE and PATENTS-NOTICE.md, extracted from that wheel, so the page links to exactly the files the package carries; `PATENTS-NOTICE.txt`, a plain-text copy; and `licence.html`, `notice.html`, `patents.html`, which show each file's text as it is in the wheel (GitHub Pages serves the raw files for download, not display). Written by `tools/licence_pages.py`; `tools/test_licence_pages.py` checks them against the wheel and the wheel against PyPI. |
| `sample/` | The sample pack, since 2026-10-24: the WP2 ALOHA robot-arm pack on schema 1.14, with its regulation clauses (`…-k8-mapped.evidence-pack.json`, sha256 `9bd78435…8364`), signed with the HSM key on 2026-10-24. The earlier sample, the same campaign on schema 1.12 signed on 2026-10-04 (`…-k8.evidence-pack.json`, `5d605343…d346`), stays at its old URL, linked from the sample section. |

## The privacy promise, and how it is enforced

1. The base policy permits connections to this site only (`connect-src 'self'`), so a
   pack can never be sent to a third party.
2. After the verifier loads, `app.mjs` adds a second policy with `connect-src 'none'`
   and `script-src 'none'`. Policies only add up, so from then on the page can make no
   connection at all.
3. It then attempts a fetch. If the browser lets it through, the page refuses to accept
   a file.

What a content security policy cannot stop: the visitor themselves navigating away, and
browser extensions, which run outside the page's policy.

## Go-live checklist

Done on 2026-10-13. certanix-site is a public repository: anything pushed, even a branch,
is published.

- [x] Counsel has reviewed and approved PATENTS-NOTICE.md (2026-10-13).
- [x] certanix-verify 0.14.0 released on PyPI (2026-10-13); the `#prerelease` notice removed.
- [x] A link from the home page to `/verify/`.

## Changing the sample pack

Axel chooses the pack. Any signing happens only at cosign's own PIN prompt, entered by
Axel. Then add the file to `verify/sample/` (keep the earlier ones: their URLs are cited elsewhere) and change the `data-sample-*` attributes of
`<section id="sample">` in `index.html` (`href`, `sha256`, `schema`, `description`). The
sample is a download, not fetched by the verifier, so the page's no-network rule is
unchanged.

## Testing locally

```bash
tools/vendor-pyodide.sh                      # only when changing the Pyodide version
tools/build-verifier.sh /path/to/certanix_verify-0.16.0-py3-none-any.whl
python3 -m http.server 8765 --bind 127.0.0.1  # then open http://127.0.0.1:8765/verify/
```

The conformance run (every public test case through this page's `runCli` and through the
CLI, compared byte for byte) lives in the private repository, with the test cases.
