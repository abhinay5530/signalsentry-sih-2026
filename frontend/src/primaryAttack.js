/**
 * Primary attack vs supporting indicators (Incident Details only).
 *
 * Does not change stored detections. Selection is deterministic:
 * 1) If event.scenario_id prefix maps to an attack family present on this event, use that family.
 * 2) Else pick the most specific family present using ATTACK_PRIORITY below.
 * 3) Else first detection (stable id order).
 *
 * scenario_id is synthetic demo metadata (e.g. xxe_ok), not live intel.
 */

export const ATTACK_PRIORITY = [
  "XML External Entity Injection (XXE)",
  "Web shell upload indicators",
  "SQL Injection",
  "Cross-Site Scripting (XSS)",
  "Server-Side Request Forgery (SSRF)",
  "Command Injection",
  "Local File Inclusion / Remote File Inclusion (LFI/RFI)",
  "Directory Traversal",
  "HTTP Parameter Pollution (HPP)",
  "Credential Stuffing / Brute Force",
  "Typosquatting / URL spoofing",
  "ANOMALOUS_URL",
];

/** Longest prefix first so "webshell" is not shadowed. */
const SCENARIO_PREFIX_TO_TYPE = [
  ["webshell", "Web shell upload indicators"],
  ["sqli", "SQL Injection"],
  ["xss", "Cross-Site Scripting (XSS)"],
  ["ssrf", "Server-Side Request Forgery (SSRF)"],
  ["cmd", "Command Injection"],
  ["lfi", "Local File Inclusion / Remote File Inclusion (LFI/RFI)"],
  ["trav", "Directory Traversal"],
  ["hpp", "HTTP Parameter Pollution (HPP)"],
  ["brute", "Credential Stuffing / Brute Force"],
  ["typo", "Typosquatting / URL spoofing"],
  ["xxe", "XML External Entity Injection (XXE)"],
];

/** Outcome/sequence codes — omit from supporting cards so they are not shown as extra successes. */
const SUPPORTING_SKIP_CODES = new Set([
  "fail_then_success",
  "error_then_data",
  "auth_fail_then_200",
  "upload_then_access",
  "not_url_only",
  "incomplete_http",
  "blocked_or_error",
  "ml_support",
]);

function typeFromScenario(scenarioId) {
  const sid = String(scenarioId || "").toLowerCase();
  if (!sid) return null;
  for (const [prefix, type] of SCENARIO_PREFIX_TO_TYPE) {
    if (sid === prefix || sid.startsWith(prefix + "_") || sid.startsWith(prefix)) {
      return type;
    }
  }
  return null;
}

export function selectPrimaryAttack(detections = [], scenarioId) {
  const list = Array.isArray(detections) ? detections.slice() : [];
  if (!list.length) {
    return { primary: null, supporting: [], reasonKey: "none", scenarioType: null };
  }
  if (list.length === 1) {
    return { primary: list[0], supporting: [], reasonKey: "single", scenarioType: typeFromScenario(scenarioId) };
  }

  const scenarioType = typeFromScenario(scenarioId);
  if (scenarioType) {
    const hit = list.find((d) => d.attack_type === scenarioType);
    if (hit) {
      return {
        primary: hit,
        supporting: list.filter((d) => d.id !== hit.id),
        reasonKey: "scenario",
        scenarioType,
      };
    }
  }

  for (const type of ATTACK_PRIORITY) {
    const hit = list.find((d) => d.attack_type === type);
    if (hit) {
      return {
        primary: hit,
        supporting: list.filter((d) => d.id !== hit.id),
        reasonKey: "priority",
        scenarioType,
      };
    }
  }

  const primary = list[0];
  return {
    primary,
    supporting: list.slice(1),
    reasonKey: "fallback",
    scenarioType,
  };
}

export function analystExplanation(primary, supporting, reasonKey) {
  if (!primary) return "";
  const name = primary.attack_type;
  const n = supporting.length;
  const overlap =
    n > 0
      ? " Multiple indicators were observed in the same HTTP transaction. Other matched signatures are retained as supporting indicators, not as separate successful attacks."
      : "";

  let why;
  if (name.startsWith("XML External Entity")) {
    why = `${name} is shown as the primary attack because the request contains XXE-specific DOCTYPE/ENTITY indicators.`;
  } else if (reasonKey === "scenario") {
    why = `${name} is shown as the primary attack because synthetic scenario metadata on this event identifies that family, and a matching detection is present.`;
  } else if (reasonKey === "priority") {
    why = `${name} is shown as the primary attack because it is the most specific family among overlapping signatures on this transaction (documented priority order).`;
  } else if (reasonKey === "single") {
    why = `${name} is the only detection on this HTTP event.`;
  } else {
    why = `${name} is shown as the primary attack (first stored detection; no higher-priority family matched).`;
  }

  const outcome =
    primary.status === "CONFIRMED"
      ? " Status is CONFIRMED based on correlated HTTP evidence available in the dataset (for example a same-path fail-then-success sequence). This is not proof that a server was compromised."
      : primary.status === "ATTEMPT"
        ? " Status ATTEMPT means a suspicious pattern was detected without sufficient corroborating HTTP outcome evidence."
        : primary.status === "UNKNOWN"
          ? " Status UNKNOWN means available HTTP/application-layer metadata is insufficient to judge outcome."
          : "";

  return why + overlap + outcome;
}

/** Signature tokens for supporting cards — omit sequence/CONFIRMED-style codes so they are not shown as separate successes. */
export function supportingEvidence(detection) {
  const items = detection.evidence || [];
  const sig = items.filter((e) => e && !SUPPORTING_SKIP_CODES.has(e.code));
  return sig.length ? sig : items.filter((e) => e && e.code !== "ml_support");
}
