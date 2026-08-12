// search.js — the pure half of global search: group /api/search results by
// their source trail and reduce each record to one linkable line. No DOM, no
// network — the view renders what this returns, via textContent like every
// other record-derived string.

export const SEARCH_MIN_CHARS = 3;

const SOURCES = ["audit", "capture", "journal"];

// Results arrive flat; the view shows them grouped by source, in the fixed
// audit → capture → journal order, with anything unrecognized last under
// "other" rather than dropped — a new backend source should show up oddly,
// not silently vanish. Within a group, server order stands.
export function groupResults(results) {
  const groups = new Map();
  for (const src of SOURCES) groups.set(src, []);
  groups.set("other", []);
  for (const r of results ?? []) {
    if (!r || typeof r !== "object") continue;
    (groups.get(r.source) ?? groups.get("other")).push(r);
  }
  for (const [src, list] of groups) {
    if (list.length === 0) groups.delete(src);
  }
  return groups;
}

function trim(s, cap = 160) {
  const t = String(s);
  return t.length > cap ? t.slice(0, cap) + "…" : t;
}

// One result → { session, ts, text }: the session keys the detail link (null
// stays null — "(unattributed)" is the view's word), the text is a one-line
// summary shaped per source, falling back to trimmed JSON for shapes this
// module does not know yet.
export function resultLine(result) {
  const rec = result?.record ?? {};
  const session = rec.session ?? null;
  const ts = rec.ts ?? null;
  if (result?.source === "audit") {
    const verdict = rec.decision ?? "?";
    const target = [rec.method, rec.host, rec.path].filter(Boolean).join(" ");
    return { session, ts,
             text: `${verdict} ${target}${rec.reason ? " — " + rec.reason : ""}` };
  }
  if (result?.source === "capture") {
    const what = rec.kind === "content_block"
      ? (rec.type === "tool_use" ? `tool_use ${rec.tool_name ?? "?"}`
                                 : trim(rec.text ?? rec.type ?? "block", 120))
      : rec.kind ?? "record";
    const model = rec.model ? ` ${rec.model}` : "";
    return { session, ts, text: `${what}${model}` };
  }
  if (result?.source === "journal") {
    const event = rec.event ?? rec.kind ?? rec.type ?? "event";
    const argv = Array.isArray(rec.argv) ? " " + trim(rec.argv.join(" "), 120) : "";
    const rc = typeof rec.rc === "number" ? ` rc ${rec.rc}` : "";
    return { session, ts, text: `${event}${argv}${rc}` };
  }
  return { session, ts, text: trim(JSON.stringify(rec) ?? "") };
}
