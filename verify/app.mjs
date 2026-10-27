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
      ? { kind: "hsm", name: HSM_KEY_NAME, bytes: hsmPem }
      : { kind: "own", name: safeName(state.key.name, "key.pub"), bytes: state.key.bytes };
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
    const keyLabel = await describeKey(key);
    render(parsed, machine, human, shown, key);
    renderCovers(parsed, covers, keyLabel);
  } catch (err) {
    $("result").hidden = false;
    $("covers").hidden = true;
    $("covers-note").hidden = true;
    $("strip").hidden = true;
    $("plain").hidden = true;
    $("verdict").className = "verdict fail";
    $("verdict").textContent = "Could not run the verifier";
    $("detail").textContent = String(err && err.message ? err.message : err);
  } finally {
    refreshButton();
  }
}

// The key the visitor chose on this page, never what the pack says about its own key.
async function describeKey(key) {
  const fp = await spkiSha256(key.bytes);
  const short = fp ? `${fp.slice(0, 4)}…${fp.slice(-4)}`.toUpperCase() : "";
  if (key.kind === "hsm") return `Certanix hardware key ${short}`.trim();
  return `Key file ${key.name} ${short}`.trim();
}

// One plain sentence per failure class: the page's own exit-code table, so the wording
// lives in one place.
function meaningOf(status) {
  for (const row of document.querySelectorAll("table.codes tbody tr")) {
    const cells = row.querySelectorAll("td");
    if (cells.length >= 3 && cells[1].textContent === status) return cells[2].textContent;
  }
  return null;
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

  const plain = $("plain");
  const meaning = verified ? null : meaningOf(status);
  plain.textContent = meaning || "";
  plain.hidden = !meaning;

  $("detail").textContent = parsed ? parsed.detail : (machine.stderr || human.stderr).trim();

  const meta = $("meta");
  meta.replaceChildren();
  const add = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    meta.append(...termAndValue(label, value));
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
//
// The page arranges that text for reading: a summary strip, clauses grouped by framework,
// a clause's route and stated limit in their own boxes. It relies on the shapes
// certanix-verify 0.16.1 writes (its _summary.py). A row that does not have the expected
// shape is shown as the verifier's raw row text, so nothing can silently disappear.
// Grouping compares exact strings, and the page says when it has grouped.

const NOT_RECORDED = "not recorded in this pack";
const ROUTE_LABEL = "How it can apply: ";
const NOT_SHOWN_LABEL = "Not shown by this pack: ";
const MORE = "… and ";
const REQUIREMENTS = "Requirements this evidence relates to";
const UNRELATED = "Frameworks considered and not related";
const OUTCOME = /^(\d+) passed, (\d+) failed(?:, (\d+) with another outcome \(error\))?$/;
const STRIP_CHIPS = 3;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Colours by the verifier's exact framework label; anything else is neutral grey.
const FRAMEWORK_COLOURS = new Map([
  ["Machinery Regulation", "fw-teal"],
  ["EU AI Act", "fw-violet"],
  ["Cyber Resilience Act", "fw-amber"],
  ["EU Basic Regulation (civil aviation)", "fw-blue"],
  ["UAS operations (Regulation (EU) 2019/947)", "fw-blue"],
]);
const colourOf = (label) => FRAMEWORK_COLOURS.get(label) || "fw-grey";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

// Monospace for hashes, IDs and file names (one word, not a plain number); proportional
// for everything that reads as language.
const looksLikeId = (s) => typeof s === "string" && s !== "" && !/\s/.test(s) && !/^[\d.,%]+$/.test(s);

function termAndValue(label, value) {
  const dt = el("dt", "", label);
  const dd = el("dd");
  if (Array.isArray(value)) {
    dd.className = "list";
    for (const item of value) dd.append(el("span", looksLikeId(item) ? "mono" : "", item));
  } else {
    dd.textContent = String(value);
    dd.className = looksLikeId(value) ? "mono" : "prose";
  }
  return [dt, dd];
}

const sectionNamed = (sections, title) => sections.find((s) => s && s.title === title);
function rowValue(section, label) {
  const rows = section && Array.isArray(section.rows) ? section.rows : [];
  const row = rows.find((r) => Array.isArray(r) && r[0] === label);
  return row ? row[1] : undefined;
}
const recorded = (v) => typeof v === "string" && v !== "" && v !== NOT_RECORDED;
const lines = (value) => (Array.isArray(value) ? value.map(String) : [String(value)]);

// A clause row, as the verifier writes it: the citation alone, or the citation followed by
// the route and the stated limit, each with its label, in that order. null otherwise.
function parseClause(value) {
  const items = Array.isArray(value) ? value : [value];
  if (!items.length || items.length > 3 || !items.every((x) => typeof x === "string")) return null;
  const [citation, ...rest] = items;
  if (citation.startsWith(ROUTE_LABEL) || citation.startsWith(NOT_SHOWN_LABEL)) return null;
  const clause = { citation };
  for (const item of rest) {
    if (item.startsWith(ROUTE_LABEL) && clause.route === undefined && clause.notShown === undefined) {
      clause.route = item.slice(ROUTE_LABEL.length);
    } else if (item.startsWith(NOT_SHOWN_LABEL) && clause.notShown === undefined) {
      clause.notShown = item.slice(NOT_SHOWN_LABEL.length);
    } else {
      return null;
    }
  }
  return clause;
}

// The verifier's raw row: its label and every line of its value, as written.
function rawRow(label, value) {
  const box = el("div", "raw");
  if (label) box.append(el("span", "k", label));
  for (const line of lines(value)) box.append(el("span", "line", line));
  return box;
}

function tile(label, value, { wide = false, mono = false } = {}) {
  const t = el("div", wide ? "tile wide" : "tile");
  t.append(el("span", "k", label));
  if (value instanceof Node) t.append(value);
  else t.append(el("span", mono ? "v mono-font" : "v", value));
  return t;
}

function renderStrip(sections, keyLabel) {
  const strip = $("strip");
  strip.replaceChildren();
  const system = sectionNamed(sections, "System tested");
  const task = sectionNamed(sections, "Task and pass criterion");
  const results = sectionNamed(sections, "Results");
  const run = sectionNamed(sections, "When and where it ran");
  const requirements = sectionNamed(sections, REQUIREMENTS);

  // System tested: the policy repository as written, else the task, else no tile.
  const repo = rowValue(system, "Policy repository");
  const taskId = rowValue(task, "Task");
  const name = recorded(repo) ? repo : recorded(taskId) ? taskId : null;
  if (name) strip.append(tile("System tested", name, { mono: looksLikeId(name) }));

  const outcome = rowValue(results, "Outcome");
  const executed = rowValue(results, "Scenarios executed");
  const counts = typeof outcome === "string" ? OUTCOME.exec(outcome) : null;
  if (counts && typeof executed === "string" && /^\d+$/.test(executed)) {
    strip.append(tile("Result", `${counts[1]} of ${executed} scenarios passed`));
  } else if (outcome !== undefined) {
    strip.append(tile("Result", lines(outcome).join(" ")));
  }

  const ranAt = rowValue(run, "Ran at");
  if (recorded(ranAt)) {
    const d = /^(\d{4})-(\d{2})-(\d{2})(?:T|$)/.exec(ranAt);
    const month = d ? MONTHS[Number(d[2]) - 1] : undefined;
    strip.append(tile("Tests ran", d && month ? `${Number(d[3])} ${month} ${d[1]}` : ranAt));
  }

  strip.append(tile("Verified with", keyLabel));

  if (counts) {
    const bar = el("div", "bar");
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label", outcome);
    const segments = [
      ["pass", Number(counts[1]), "passed"],
      ["fail", Number(counts[2]), "failed"],
      ["other", Number(counts[3] || 0), "other outcome"],
    ];
    for (const [kind, n, word] of segments) {
      if (!n) continue;
      const seg = el("div", `seg ${kind}`, `${n} ${word}`);
      seg.style.flexGrow = String(n); // CSSOM, which the content security policy allows
      bar.append(seg);
    }
    strip.append(bar);
  }

  // Failed: at most three IDs, then "+N more"; the full list stays in Results below.
  const failing = rowValue(results, "Failing scenarios");
  if (Array.isArray(failing)) {
    const ids = failing.filter((x) => typeof x === "string" && !x.startsWith(MORE));
    const moreLine = failing.find((x) => typeof x === "string" && x.startsWith(MORE));
    const notListed = moreLine ? Number((/^… and (\d+) more/.exec(moreLine) || [])[1] || 0) : 0;
    const box = el("span", "v chips");
    for (const id of ids.slice(0, STRIP_CHIPS)) box.append(el("span", "chip id failed", id));
    const rest = ids.length - Math.min(ids.length, STRIP_CHIPS) + notListed;
    if (rest > 0) box.append(el("span", "more", `+${rest} more`));
    strip.append(tile("Failed", box, { wide: true }));
  } else if (failing !== undefined) {
    strip.append(tile("Failed", lines(failing).join(" "), { wide: true }));
  }

  // EU provisions: one chip per framework with its count, or the verifier's note.
  if (requirements) {
    const rows = Array.isArray(requirements.rows) ? requirements.rows : [];
    const tally = new Map();
    const extra = [];
    for (const row of rows) {
      if (!Array.isArray(row)) continue;
      if (row[0] === "") extra.push(...lines(row[1]));
      else tally.set(String(row[0]), (tally.get(String(row[0])) || 0) + 1);
    }
    if (tally.size) {
      const box = el("span", "v chips");
      for (const [label, n] of tally) {
        const chip = el("span", `chip ${colourOf(label)}`);
        chip.append(el("span", "dot"), el("span", "", `${label} · ${n}`));
        box.append(chip);
      }
      for (const line of extra) box.append(el("span", "more", line));
      strip.append(tile("EU provisions", box, { wide: true }));
    } else if (typeof requirements.note === "string") {
      strip.append(tile("EU provisions", requirements.note, { wide: true }));
    }
  }
  strip.hidden = false;
}

function renderGenericRows(section, body) {
  const rows = Array.isArray(section.rows) ? section.rows : [];
  if (!rows.length) return;
  const dl = el("dl", "meta");
  for (const row of rows) {
    if (!Array.isArray(row)) continue;
    const [label, value] = row;
    if (section.title === "Results" && label === "Failing scenarios" && Array.isArray(value)) {
      const dt = el("dt", "", label);
      const dd = el("dd", "chips");
      for (const item of value) {
        const id = typeof item === "string" && !item.startsWith(MORE);
        dd.append(id ? el("span", "chip id failed", item) : el("span", "", item));
      }
      dl.append(dt, dd);
    } else {
      dl.append(...termAndValue(String(label), value));
    }
  }
  body.append(dl);
}

function citationParts(citation) {
  const m = /^(.*?\(CELEX [^)]*\)), (.+)$/s.exec(citation);
  return m ? { clause: m[2], act: m[1] } : { clause: citation, act: null };
}

function renderRequirements(section, body) {
  const rows = Array.isArray(section.rows) ? section.rows : [];
  const groups = new Map();
  const extra = [];
  for (const row of rows) {
    if (!Array.isArray(row)) {
      extra.push(rawRow("", row));
      continue;
    }
    const [label, value] = row;
    if (label === "") {
      extra.push(el("p", "notshown-more", lines(value).join(" ")));
      continue;
    }
    const key = String(label);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ label: key, value, clause: parseClause(value) });
  }

  for (const [label, items] of groups) {
    const group = el("div", `fw-group ${colourOf(label)}`);
    const band = el("div", "fw-band");
    band.append(
      el("span", "name", label),
      el("span", "count", `${items.length} ${items.length === 1 ? "provision" : "provisions"}`),
    );
    group.append(band);

    // The route is shown once for the group only when every clause in it is well formed
    // and carries the same route, character for character.
    const routes = items.map((i) => (i.clause ? i.clause.route : undefined));
    const shared =
      items.length > 1 && routes.every((r) => typeof r === "string" && r === routes[0]) ? routes[0] : null;
    if (shared !== null) {
      const box = el("div", "fw-route");
      box.append(
        el("span", "k", "How these provisions can apply to this product"),
        el("p", "", shared),
        el("p", "grouped", "Identical text shown once for this group"),
      );
      group.append(box);
    }

    const cards = el("div", "cards");
    for (const item of items) {
      const card = el("div", "card");
      if (!item.clause) {
        card.append(rawRow(item.label, item.value));
        cards.append(card);
        continue;
      }
      const { clause, act } = citationParts(item.clause.citation);
      card.append(el("p", "ref", clause));
      if (act) card.append(el("p", "act", act));
      if (item.clause.route !== undefined && shared === null) {
        const route = el("div", "route");
        route.append(el("span", "k", "How it can apply"), el("p", "", item.clause.route));
        card.append(route);
      }
      if (item.clause.notShown !== undefined) {
        const limit = el("div", "limit");
        limit.append(el("span", "k", "Not shown by this pack"), el("p", "", item.clause.notShown));
        card.append(limit);
      }
      cards.append(card);
    }
    group.append(cards);
    body.append(group);
  }
  body.append(...extra);
}

function renderUnrelated(section, body) {
  const rows = Array.isArray(section.rows) ? section.rows : [];
  if (!rows.length) return;
  const box = el("div", "unrelated");
  const dl = el("dl");
  for (const row of rows) {
    if (!Array.isArray(row)) {
      box.append(rawRow("", row));
      continue;
    }
    const [label, value] = row;
    dl.append(el("dt", "", label === "" ? "" : label));
    const dd = el("dd");
    for (const line of lines(value)) dd.append(el("span", "", line));
    dl.append(dd);
  }
  box.prepend(dl);
  body.append(box);
}

function renderCovers(parsed, covers, keyLabel) {
  const box = $("covers");
  const body = $("covers-body");
  const note = $("covers-note");
  const strip = $("strip");
  box.hidden = true;
  note.hidden = true;
  strip.hidden = true;
  strip.replaceChildren();
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

  const sections = (Array.isArray(out.summary.sections) ? out.summary.sections : []).filter(
    (s) => s && typeof s === "object",
  );
  renderStrip(sections, keyLabel);

  $("covers-title").textContent = "What this pack covers";
  for (const section of sections) {
    // The regulation-references disclaimer: the verifier's own text, verbatim, shown
    // directly above the clauses it qualifies, and only when the pack carries schema 1.14
    // clauses.
    if (typeof section.disclaimer === "string") {
      body.append(el("p", "disclaimer", section.disclaimer));
    }
    body.append(el("h4", "", section.title));
    if (section.note) body.append(el("p", "note", section.note));
    if (section.title === REQUIREMENTS) renderRequirements(section, body);
    else if (section.title === UNRELATED) renderUnrelated(section, body);
    else renderGenericRows(section, body);
  }
  box.hidden = false;
}

// ---------------------------------------------------------------------------------- //
// Light and dark
// ---------------------------------------------------------------------------------- //

// The system setting by default; the corner toggle overrides it, remembered per browser.
// Storage can be missing or refuse (private windows, blocked site data): the page works
// without it.
const THEME_KEY = "certanix-verify-theme";
const prefersLight = () => window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
const currentTheme = () => document.documentElement.dataset.theme || (prefersLight() ? "light" : "dark");

function setupTheme() {
  const button = $("theme-toggle");
  let stored = null;
  try {
    stored = localStorage.getItem(THEME_KEY);
  } catch {
    stored = null;
  }
  if (stored === "light" || stored === "dark") document.documentElement.dataset.theme = stored;
  const label = () => {
    const next = currentTheme() === "dark" ? "Light theme" : "Dark theme";
    $("theme-label").textContent = next;
    button.setAttribute("aria-label", `Switch to the ${next.toLowerCase()}`);
  };
  button.addEventListener("click", () => {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // not remembered; the choice still applies to this page
    }
    label();
  });
  if (window.matchMedia) window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", label);
  label();
  button.hidden = false;
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
  setupTheme();
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
  for (const [label, value] of rows) runtime.append(...termAndValue(label, value));
  runtime.hidden = false;
  refreshButton();
}

start();
