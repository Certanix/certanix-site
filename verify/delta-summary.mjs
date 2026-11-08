// The rows the page shows for a verified delta report, read from its signed fields.
//
// certanix-verify 0.17.0 verifies a delta report but writes no summary of it ("Summary not
// available for this artifact type"). The public-demo plan (C.12, C.13) has the page show
// what a reader needs from the signed fields themselves, labelled as such, and only after
// the verifier returned exit 0. This module only reads and arranges: it computes no
// verdict, and it returns null for anything that is not a well-formed delta report, so the
// page then shows the verifier's note alone.

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isCount = (v) => Number.isInteger(v) && v >= 0;

function failedOf(passed, total) {
  return isCount(passed) && isCount(total) && passed <= total ? `${total - passed} of ${total}` : null;
}

export function deltaSummaryRows(doc) {
  if (!isObject(doc) || doc.artifact_type !== "delta-report") return null;
  const { baseline, candidate, battery, transitions, pass_rate: rate } = doc;
  if (!isObject(baseline) || !isObject(candidate) || !isObject(battery) || !isObject(rate)) return null;
  if (!Array.isArray(transitions) || !Array.isArray(battery.scenario_ids)) return null;
  if (!transitions.every((t) => isObject(t) && typeof t.scenario_id === "string")) return null;

  const baselineFailed = failedOf(rate.baseline_passed, rate.baseline_total);
  const candidateFailed = failedOf(rate.candidate_passed, rate.candidate_total);
  if (baselineFailed === null || candidateFailed === null) return null;

  const compared = transitions.map((t) => t.scenario_id);
  const inBattery = new Set(battery.scenario_ids);
  const inTransitions = new Set(compared);
  const addedOrRemoved =
    compared.filter((id) => !inBattery.has(id)).length +
    battery.scenario_ids.filter((id) => !inTransitions.has(id)).length;
  const changed = transitions
    .filter((t) => t.kind !== "unchanged")
    .map((t) => `${t.scenario_id}: ${t.baseline_status} to ${t.candidate_status} (${t.kind})`);

  return [
    ["Baseline pack, canonical SHA-256", String(baseline.canonical_sha256)],
    ["Candidate pack, canonical SHA-256", String(candidate.canonical_sha256)],
    ["Scenarios compared", String(compared.length)],
    ["Failed in the baseline", baselineFailed],
    ["Failed in the candidate", candidateFailed],
    ["Verdicts changed", changed.length ? [String(changed.length), ...changed] : "0"],
    ["Scenarios added or removed", addedOrRemoved ? String(addedOrRemoved) : "none"],
  ];
}
