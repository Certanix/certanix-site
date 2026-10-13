// The in-browser verifier: certanix-verify, unchanged, running in Pyodide.
//
// This file loads a Python interpreter and installs the certanix-verify wheel into it. It
// does not verify anything itself. There is no canonicalisation, no signature check and
// no schema logic in JavaScript: `runCli` hands an argument list to
// `certanix_verify.cli.main`, the same function the `certanix-verify` command runs, and
// returns its exit code and output. The page and the conformance harness both go through
// `runCli`, so the corpus tests the path a visitor uses.
//
// Every file it fetches comes from this site, during load. Files a visitor chooses are
// read locally and written into the interpreter's in-memory file system, never sent.

import { loadPyodide } from "./runtime/pyodide/pyodide.mjs";

const RUNTIME = new URL("./runtime/", import.meta.url);

// The only Python in this file: call main(argv) with stdout and stderr captured, and turn
// a SystemExit (argparse on a bad invocation) into the code the process would exit with.
const RUNNER = `
import contextlib, io, sys
from certanix_verify.cli import main as _certanix_verify_main

def _certanix_run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = _certanix_verify_main(list(argv))
        except SystemExit as exc:
            if exc.code is None:
                code = 0
            elif isinstance(exc.code, int):
                code = exc.code
            else:
                print(exc.code, file=sys.stderr)
                code = 1
    return [code, out.getvalue(), err.getvalue()]
`;

let ready = null;

/** Load the interpreter and the verifier once. Resolves to a description of what runs. */
export function load() {
  if (!ready) ready = boot();
  return ready;
}

async function boot() {
  const bundle = await (
    await fetch(new URL("verifier/bundle.json", RUNTIME), { cache: "no-store" })
  ).json();

  const pyodide = await loadPyodide({
    indexURL: new URL("pyodide/", RUNTIME).href,
    stdout: () => {},
    stderr: () => {},
  });
  // cryptography and its dependencies, from the vendored lock; Pyodide checks each wheel
  // against the lock's sha256.
  await pyodide.loadPackage(["cryptography"], { messageCallback: () => {} });

  const site = pyodide.runPython("import site; site.getsitepackages()[0]");
  for (const wheel of bundle.wheels) {
    // Subresource Integrity: the browser refuses a wheel whose bytes are not these.
    const response = await fetch(new URL(`verifier/${wheel.file}`, RUNTIME), {
      integrity: wheel.integrity,
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`could not load ${wheel.file}`);
    pyodide.unpackArchive(await response.arrayBuffer(), "zip", { extractDir: site });
  }

  pyodide.runPython(RUNNER);
  // Import everything verification can reach now, while loading is still allowed, so no
  // module is fetched or compiled after the page has closed its network.
  const versions = pyodide
    .runPython(
      `
import json, sys
import certanix_verify, certanix_verify.cli, certanix_verify._vault
import cryptography, asn1crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography import x509
json.dumps({
  "certanix_verify": certanix_verify.__version__,
  "python": sys.version.split()[0],
  "cryptography": cryptography.__version__,
  "asn1crypto": asn1crypto.__version__,
})
`,
    )
    .toString();

  pyodide.FS.mkdirTree("/work");
  const run = pyodide.globals.get("_certanix_run");
  return {
    pyodide,
    run,
    bundle,
    versions: { ...JSON.parse(versions), pyodide: pyodide.version },
  };
}

let sequence = 0;

/**
 * Run certanix-verify with `argv`, after writing `files` into the interpreter.
 *
 * `files` maps a relative path to its bytes (Uint8Array); each lands under a fresh
 * directory, and `argv` refers to them through the token `{W}` (that directory). The
 * directory is removed afterwards, so nothing from one run is visible to the next.
 * Returns { exitCode, stdout, stderr }.
 */
export async function runCli(argv, files) {
  const { pyodide, run } = await load();
  const work = `/work/${++sequence}`;
  const written = [];
  pyodide.FS.mkdirTree(work);
  try {
    for (const [name, bytes] of Object.entries(files)) {
      const path = `${work}/${name}`;
      pyodide.FS.mkdirTree(path.slice(0, path.lastIndexOf("/")));
      pyodide.FS.writeFile(path, bytes);
      written.push(path);
    }
    const args = argv.map((a) => a.split("{W}").join(work));
    const proxy = run(pyodide.toPy(args));
    const [exitCode, stdout, stderr] = proxy.toJs();
    proxy.destroy();
    return { exitCode, stdout, stderr, workdir: work };
  } finally {
    removeTree(pyodide.FS, work);
  }
}

function removeTree(FS, path) {
  for (const entry of FS.readdir(path)) {
    if (entry === "." || entry === "..") continue;
    const child = `${path}/${entry}`;
    if (FS.isDir(FS.stat(child).mode)) removeTree(FS, child);
    else FS.unlink(child);
  }
  FS.rmdir(path);
}
