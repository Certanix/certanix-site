// certanix.eu/verify: the page around the in-browser verifier (engine.mjs).
//
// Order matters, and is the privacy promise the page makes:
//   1. load the interpreter and the verifier from this site;
//   2. close the network: add a content security policy that forbids every connection;
//   3. check that the browser applied it, by attempting a fetch that must now fail;
//   4. only then accept a file.
// If step 3 finds the network still open, no file is accepted at all.
//
// This file builds an argument list and displays what certanix-verify printed. It makes
// no verification decision of its own: the verdict shown is the verifier's JSON output.

import { load, runCli } from "./engine.mjs";

const $ = (id) => document.getElementById(id);
const HSM_KEY_NAME = "certanix-hsm.pub";

const state = { pack: null, key: null, bundle: null };

function setStatus(kind, text) {
  $("status").dataset.state = kind;
  $("status-text").textContent = text;
}

// ---------------------------------------------------------------------------------- //
// The network lock
// ---------------------------------------------------------------------------------- //

// Policies only ever add up: a second policy can make the page stricter, never looser.
const LOCKDOWN =
  "connect-src 'none'; script-src 'none'; img-src data:; frame-src 'none'; worker-src 'none'; form-action 'none'";

function closeNetwork() {
  const meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = LOCKDOWN;
  document.head.appendChild(meta);
}

async function networkIsClosed() {
  try {
    await fetch(new URL("runtime/verifier/bundle.json", import.meta.url), { cache: "no-store" });
    return false; // the browser let a request out: the lock is not in force
  } catch {
    return true;
  }
}

// ---------------------------------------------------------------------------------- //
// Fingerprints, for display only
// ---------------------------------------------------------------------------------- //

function pemToDer(pem) {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const raw = atob(body);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function spkiSha256(pemBytes) {
  try {
    const der = pemToDer(new TextDecoder().decode(pemBytes));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
    return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

async function fileSha256(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------------- //
// Inputs
// ---------------------------------------------------------------------------------- //

// A name safe to use as a file name inside the interpreter, and recognisable in output.
function safeName(name, fallback) {
  const cleaned = (name || "").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^\.+/, "");
  return cleaned || fallback;
}

async function readFile(file) {
  return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
}

function refreshButton() {
  const keyReady = currentKeyChoice() === "hsm" || state.key;
  $("verify").disabled = !(state.pack && keyReady && document.body.dataset.locked === "yes");
}

function currentKeyChoice() {
  return document.querySelector('input[name="key"]:checked').value;
}

// Each choice of file gets a number; only the latest one may become the pack.
let packChoice = 0;

async function takePack(file) {
  if (!file || document.body.dataset.locked !== "yes") return;
  // Until the new file is read, there is no pack: the previous one must not be verified in
  // its place, and Verify stays disabled.
  const choice = ++packChoice;
  state.pack = null;
  $("result").hidden = true;
  $("pack-name").textContent = `${file.name} (reading…)`;
  refreshButton();
  const pack = await readFile(file);
  if (choice !== packChoice) return;
  state.pack = pack;
  $("pack-name").textContent = `${file.name} (${pack.bytes.length.toLocaleString()} bytes)`;
  refreshButton();
}

function wireInputs() {
  const drop = $("drop");
  $("pack-input").addEventListener("change", (e) => takePack(e.target.files[0]));
  for (const type of ["dragenter", "dragover"]) {
    drop.addEventListener(type, (e) => {
      e.preventDefault();
      if (document.body.dataset.locked === "yes") drop.classList.add("over");
    });
  }
  for (const type of ["dragleave", "drop"]) {
    drop.addEventListener(type, () => drop.classList.remove("over"));
  }
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    takePack(e.dataTransfer.files[0]);
  });
  // A file dropped anywhere else must not make the browser navigate to it.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  for (const radio of document.querySelectorAll('input[name="key"]')) {
    radio.addEventListener("change", () => {
      $("own-key").hidden = currentKeyChoice() !== "own";
      refreshButton();
    });
  }
  $("key-input").addEventListener("change", async (e) => {
    state.key = e.target.files[0] ? await readFile(e.target.files[0]) : null;
    refreshButton();
  });
  $("bundle-input").addEventListener("change", async (e) => {
    state.bundle = e.target.files[0] ? await readFile(e.target.files[0]) : null;
  });
  $("verify").addEventListener("click", verify);
}

// ---------------------------------------------------------------------------------- //
// Verify
// ---------------------------------------------------------------------------------- //

function isStandalone(bytes) {
  // A signed artifact that is not an evidence pack names its own type. Choosing the mode
  // is the command line's job too (--standalone); the verifier still decides the result.
  try {
    const doc = JSON.parse(new TextDecoder().decode(bytes));
    return doc !== null && typeof doc === "object" && "artifact_type" in doc;
  } catch {
    return false;
  }
}

function buildInvocation(hsmPem) {
  const packName = safeName(state.pack.name, "evidence-pack.json");
  const key =
    currentKeyChoice() === "hsm"
      ? { name: HSM_KEY_NAME, bytes: hsmPem }
      : { name: safeName(state.key.name, "key.pub"), bytes: state.key.bytes };
  const files = { [`pack/${packName}`]: state.pack.bytes, [`key/${key.name}`]: key.bytes };
  const argv = ["verify", `{W}/pack/${packName}`, "--key", `{W}/key/${key.name}`];
  const shown = ["certanix-verify", "verify", packName, "--key", key.name];

  const bundle = $("byte-exact").open && state.bundle;
  if (bundle) {
    const bundleName = safeName(state.bundle.name, "pack.bundle");
    files[`bundle/${bundleName}`] = state.bundle.bytes;
    argv.push("--bundle", `{W}/bundle/${bundleName}`);
    shown.push("--bundle", bundleName);
  } else if (isStandalone(state.pack.bytes)) {
    argv.push("--standalone");
    shown.push("--standalone");
  }
  return { files, argv, shown, key };
}

async function verify() {
  $("verify").disabled = true;
  try {
    const hsmPem = new TextEncoder().encode($("hsm-pem").textContent.trim() + "\n");
    const { files, argv, shown, key } = buildInvocation(hsmPem);

    const machine = await runCli([...argv, "--json"], files);
    const human = await runCli(argv, files);
    // What the pack covers: `certanix-verify show`, the same verification again and,
    // only on exit 0, the summary it read from the signed bytes. The page decides
    // nothing: it displays the sections the verifier wrote, or its one-line note.
    const covers = await runCli(["show", ...argv.slice(1), "--json"], files);
    let parsed = null;
    try {
      parsed = JSON.parse(machine.stdout);
    } catch {
      parsed = null;
    }
    render(parsed, machine, human, shown, key);
    renderCovers(parsed, covers);
  } catch (err) {
    $("result").hidden = false;
    $("covers").hidden = true;
    $("covers-note").hidden = true;
    $("verdict").className = "verdict fail";
    $("verdict").textContent = "Could not run the verifier";
    $("detail").textContent = String(err && err.message ? err.message : err);
  } finally {
    refreshButton();
  }
}

async function render(parsed, machine, human, shown, key) {
  const verdict = $("verdict");
  const code = machine.exitCode;
  const test = parsed && parsed.test_signed;
  const status = parsed ? parsed.status : code === 0 ? "OK" : `exit ${code}`;
  const verified = parsed ? parsed.verified === true : false;

  verdict.className = "verdict " + (verified ? (test ? "test" : "pass") : "fail");
  verdict.textContent = verified ? (test ? "VERIFIED WITH A TEST KEY" : "VERIFIED") : status;
  const codeSpan = document.createElement("span");
  codeSpan.className = "code";
  codeSpan.textContent = `exit ${code}`;
  verdict.append(codeSpan);

  $("detail").textContent = parsed ? parsed.detail : (machine.stderr || human.stderr).trim();

  const meta = $("meta");
  meta.replaceChildren();
  const add = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = value;
    meta.append(dt, dd);
  };
  add("File", state.pack.name);
  add("File SHA-256", await fileSha256(state.pack.bytes));
  add("Key", key.name);
  add("Key fingerprint", (await spkiSha256(key.bytes)) || "not a PEM public key");
  if (parsed) add("Schema version", parsed.schema_version);
  if (parsed) add("Verifier", parsed.verifier_version);

  const output = [human.stdout, human.stderr].filter(Boolean).join("\n").trimEnd();
  $("output").textContent = output || "(no output)";
  $("equivalent").textContent = shown.join(" ");
  $("result").hidden = false;
}

// ---------------------------------------------------------------------------------- //
// What a verified pack covers
// ---------------------------------------------------------------------------------- //

// Every string here came out of a pack, so every one is set with textContent: no
// innerHTML, no Markdown, no link made from pack content. The text itself (labels,
// escaping of control characters, truncation with "…") is the verifier's, in Python.
function renderCovers(parsed, covers) {
  const box = $("covers");
  const body = $("covers-body");
  const note = $("covers-note");
  box.hidden = true;
  note.hidden = true;
  body.replaceChildren();

  let out = null;
  try {
    out = JSON.parse(covers.stdout);
  } catch {
    out = null;
  }
  const verified = parsed && parsed.verified === true && covers.exitCode === 0;
  if (!out || typeof out !== "object") return;
  if (!verified || out.summary_status !== "shown" || !out.summary) {
    // Never anything from a pack that failed: the verifier's one line, and only that.
    if (typeof out.summary_note === "string") {
      note.textContent = out.summary_note;
      note.hidden = false;
    }
    return;
  }

  $("covers-title").textContent = "What this pack covers";
  for (const section of out.summary.sections || []) {
    // The regulation-references disclaimer: the verifier's own text, shown directly above
    // the clauses it qualifies, and only when the pack carries schema 1.14 clauses.
    if (typeof section.disclaimer === "string") {
      const d = document.createElement("p");
      d.className = "disclaimer";
      d.textContent = section.disclaimer;
      body.append(d);
    }
    const h = document.createElement("h4");
    h.textContent = String(section.title);
    body.append(h);
    if (section.note) {
      const p = document.createElement("p");
      p.className = "note";
      p.textContent = String(section.note);
      body.append(p);
    }
    const rows = Array.isArray(section.rows) ? section.rows : [];
    if (!rows.length) continue;
    const dl = document.createElement("dl");
    dl.className = "meta";
    for (const [label, value] of rows) {
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = String(label);
      if (Array.isArray(value)) {
        dd.className = "list";
        for (const item of value) {
          const line = document.createElement("span");
          line.textContent = String(item);
          dd.append(line);
        }
      } else {
        dd.textContent = String(value);
      }
      dl.append(dt, dd);
    }
    body.append(dl);
  }
  box.hidden = false;
}

// ---------------------------------------------------------------------------------- //
// The prepared sample-pack slot (empty until a pack is chosen)
// ---------------------------------------------------------------------------------- //

function showSampleIfConfigured() {
  const section = $("sample");
  const { sampleHref, sampleSha256, sampleSchema, sampleDescription } = section.dataset;
  if (!sampleHref || !sampleSha256) return;
  const file = sampleHref.split("/").pop();
  $("sample-link").href = sampleHref;
  $("sample-sha256").textContent = sampleSha256;
  $("sample-schema").textContent = sampleSchema || "";
  $("sample-description").textContent = sampleDescription || "";
  $("sample-command").textContent = `certanix-verify verify ${file} --key ${HSM_KEY_NAME}`;
  section.hidden = false;
}

// ---------------------------------------------------------------------------------- //
// Start
// ---------------------------------------------------------------------------------- //

async function start() {
  showSampleIfConfigured();
  wireInputs();

  const hsm = await spkiSha256(new TextEncoder().encode($("hsm-pem").textContent));
  if (hsm) {
    const line = document.createElement("span");
    line.textContent = ` Fingerprint of the key shown here, computed by your browser: ${hsm}.`;
    $("fingerprint-check").append(line);
  }

  let engine;
  try {
    engine = await load();
  } catch (err) {
    setStatus("error", `The verifier could not load (${err.message || err}). Use the command line below.`);
    return;
  }

  closeNetwork();
  if (!(await networkIsClosed())) {
    setStatus(
      "error",
      "This browser did not apply the network lock, so the page will not accept a file. Use the command line below.",
    );
    return;
  }

  document.body.dataset.locked = "yes";
  $("pack-input").disabled = false;
  $("drop").setAttribute("aria-disabled", "false");
  $("key-choice").disabled = false;
  setStatus(
    "ready",
    `Ready. certanix-verify ${engine.versions.certanix_verify} is loaded and this page's network is closed: from here on it cannot send anything.`,
  );

  const runtime = $("runtime");
  const verifierWheel = engine.bundle.wheels.find((w) => w.file.startsWith("certanix_verify-"));
  const rows = [
    ["certanix-verify", `${engine.versions.certanix_verify} (wheel SHA-256 ${verifierWheel.sha256})`],
    ["Python", `${engine.versions.python}, Pyodide ${engine.versions.pyodide}`],
    ["cryptography", engine.versions.cryptography],
    ["asn1crypto", engine.versions.asn1crypto],
  ];
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = value;
    runtime.append(dt, dd);
  }
  runtime.hidden = false;
  refreshButton();
}

start();
