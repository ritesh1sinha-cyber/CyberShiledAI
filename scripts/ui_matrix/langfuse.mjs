// Records the local Langfuse dashboard for the walkthrough's closing segment.
//
// Loopback only (http://127.0.0.1:3100). The sign-in credentials are read from
// docker/.env by this process; they are never logged, never written to a capture
// file, and never sent anywhere else. Nothing is uploaded: the frames land in the
// scratch capture directory beside the browser-matrix frames.
//
// Usage:  node scripts/ui_matrix/langfuse.mjs
//
// Expressions handed to Page.js must not contain a slash inside a regex literal:
// `\/` written in a template literal becomes `//`, which comments out the rest of
// the line, and the page then reports "Unexpected token 'return'".
import { readFileSync, appendFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { launchChrome, Page, sleep, log, OUT, writeResult, FRAMES } from "./cdp.mjs";

const BASE = process.env.LANGFUSE_URL || "http://127.0.0.1:3100";
const ENV = process.env.LANGFUSE_ENV || "docker/.env";
const MANIFEST = join(OUT, "langfuse_frames.jsonl");
const SUMMARY = join(OUT, "langfuse_summary.txt");
// A throwaway profile: sharing the matrix profile means a cookie from an earlier run
// signs this one in by itself, and then the credential form is never exercised even
// though the tour still works. Deleting it first makes the sign-in check mean something.
const PROFILE = join(OUT, "langfuse-profile");

function creds() {
  const out = {};
  for (const line of readFileSync(ENV, "utf8").split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) out[m[1]] = m[2].replace(/^"|"$/g, "");
  }
  if (!out.LANGFUSE_INIT_USER_EMAIL || !out.LANGFUSE_INIT_USER_PASSWORD) {
    throw new Error("Langfuse sign-in credentials missing from " + ENV);
  }
  return out;
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ status: ok ? "PASS" : "FAIL", name, detail });
  appendFileSync(SUMMARY, `${ok ? "PASS" : "FAIL"} S17-langfuse :: ${name} :: ${detail}\n`);
  log(`${ok ? "PASS" : "FAIL"} ${name} ${detail}`.trim());
}

async function poll(page, expression, want, timeoutMs = 30000, everyMs = 1500) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await page.js(expression);
    if (want(last)) return last;
    await sleep(everyMs);
  }
  return last;
}

async function typeInto(page, selector, value) {
  return page.js(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return false;
    el.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event("input", {bubbles: true}));
    el.dispatchEvent(new Event("change", {bubbles: true}));
    return true;
  })()`);
}

let seq = 0;
async function still(page, name) {
  await page.screenshot(join(FRAMES, name));
  appendFileSync(MANIFEST, JSON.stringify({
    file: name, label: "S17-langfuse", at: new Date().toISOString(), kind: "still",
  }) + "\n");
}

// The dashboard opens on a 24-hour window, and the recorded investigations are older
// than that, so every list reads "No results." until the range is widened. The picker
// is a list of buttons inside several wrapper elements, so the click has to land on the
// shortest-text match or it hits a container div and does nothing.
async function widenRange(page, label = "all time") {
  await page.js(`(() => {
    const b = [...document.querySelectorAll("button")].find(e => /hours|days|time/i.test(e.innerText || ""));
    if (b) b.click();
    return !!b;
  })()`);
  await sleep(1500);
  const picked = await page.js(`(() => {
    const needle = ${JSON.stringify(label.toLowerCase())};
    const hits = [...document.querySelectorAll("button,[role='option'],[role='menuitem']")]
      .map(e => ({ el: e, text: (e.innerText || "").trim() }))
      .filter(x => x.text.toLowerCase().indexOf(needle) >= 0)
      .sort((a, b) => a.text.length - b.text.length);
    if (!hits.length) return null;
    hits[0].el.click();
    return hits[0].text;
  })()`);
  await sleep(1200);
  // The popover survives the choice on this build, and a shot of a page half-covered by
  // its own menu is not usable evidence.
  await page.press("Escape");
  await sleep(2500);
  return picked;
}

// The dashboard's scroller is not the document: the trace panel is its own overflow
// container, so the scroll has to be applied to whichever element actually scrolls.
async function scrollMain(page, dy) {
  return page.js(`(() => {
    const cands = [...document.querySelectorAll("*")].filter(e =>
      e.scrollHeight - e.clientHeight > 120 && e.clientWidth > 300);
    cands.sort((a, b) => (b.scrollHeight - b.clientHeight) - (a.scrollHeight - a.clientHeight));
    const el = cands[0] || document.scrollingElement;
    el.scrollTop += ${dy};
    return Math.round(el.scrollTop);
  })()`);
}

async function main() {
  const c = creds();
  rmSync(PROFILE, { recursive: true, force: true });
  const chrome = await launchChrome(PROFILE);
  const page = await Page.open("");

  await page.navigate(`${BASE}/auth/sign-in`);
  await poll(page, `(() => {
    const e = document.querySelector("input[name='email']");
    const p = document.querySelector("input[name='password']");
    return !!e && !!p;
  })()`, (v) => v === true, 40000);
  const okEmail = await typeInto(page, "input[name='email']", c.LANGFUSE_INIT_USER_EMAIL);
  const okPassword = await typeInto(page, "input[name='password']", c.LANGFUSE_INIT_USER_PASSWORD);
  check("sign-in form accepts credentials", okEmail && okPassword, `email=${okEmail} password=${okPassword}`);
  await page.js(`(() => {
    const pw = document.querySelector("input[name='password']");
    const form = pw && pw.closest("form");
    if (form && form.requestSubmit) form.requestSubmit();
    else if (form) form.querySelector("button").click();
    return !!form;
  })()`);

  const landed = await poll(page, `location.pathname`, (p) => p.indexOf("sign-in") < 0, 40000);
  check("sign-in lands past the auth page", landed !== "/auth/sign-in", `path ${landed}`);

  const href = await poll(page, `(() => {
    const a = [...document.querySelectorAll("a")].map(x => x.getAttribute("href") || "");
    return a.find(h => h.indexOf("/project/") >= 0) || "";
  })()`, (h) => !!h, 40000);
  const pid = (href.split("/project/")[1] || "").split("?")[0].split("/")[0];
  check("a project is reachable after sign-in", !!pid, pid ? `project ${pid}` : "no /project/ link");
  if (!pid) throw new Error("no project id");

  // 1 fps sampler for the rest of the tour, tagged as the closing segment.
  const timer = setInterval(async () => {
    try {
      seq += 1;
      const name = `lf_${String(seq).padStart(4, "0")}.png`;
      await page.screenshot(join(FRAMES, name));
      appendFileSync(MANIFEST, JSON.stringify({
        file: name, label: "S17-langfuse", at: new Date().toISOString(), kind: "frame",
      }) + "\n");
    } catch (e) { log("sampler error " + String(e).slice(0, 120)); }
  }, 1000);

  await page.navigate(`${BASE}/project/${pid}/traces`);
  const range = await widenRange(page, "all time");
  check("the time filter is widened to show the recorded runs", !!range, `picked: ${range}`);
  const rows = await poll(page, `document.querySelectorAll("table tbody tr").length`, (n) => n >= 3, 45000);
  check("trace list renders rows", rows >= 3, `${rows} rows on screen`);
  const body = await page.text();
  const named = (body.match(/cve_investigation/g) || []).length;
  check("the dashboard shows CyberShield investigations", named > 0, `${named} trace-name cells visible`);
  await still(page, "L01_langfuse_traces.png");

  // Which trace to open is decided by the API, not by whatever the list renders first:
  // the newest recorded investigation is the one worth showing. The keys are read from
  // docker/.env and used only against the loopback address.
  const auth = "Basic " + Buffer.from(
    `${c.LANGFUSE_PROJECT_PUBLIC_KEY}:${c.LANGFUSE_PROJECT_SECRET_KEY}`).toString("base64");
  const api = async (path) => (await fetch(`${BASE}/api/public${path}`, { headers: { Authorization: auth } })).json();
  const listed = await api("/traces?limit=5");
  const wanted = (listed.data || [])[0];
  const traceId = wanted && wanted.id;
  check("the API lists a recorded investigation", !!traceId,
    traceId ? `${wanted.name} ${wanted.timestamp}` : "no traces returned");
  if (!traceId) throw new Error("no trace to show");

  await page.navigate(`${BASE}/project/${pid}/traces/${traceId}`);

  // Four of the five stages are graph nodes, so four spans is the correct expectation:
  // the Policy Guard runs before the graph and is recorded in the trace metadata, not as
  // a span. Asserting five here would be asserting something the code never did.
  const observed = await api(`/observations?traceId=${traceId}&limit=100`);
  const spans = [...new Set((observed.data || []).map((o) => o.name))].sort();
  check("the traced agent stages appear as spans",
    ["evidence", "analyst", "critic", "final_validator"].every((s) => spans.includes(s)),
    `spans: ${spans.join(", ")}`);
  const metaKeys = Object.keys(wanted.metadata || {});
  check("the trace metadata carries the guardrail and revision outcome",
    metaKeys.includes("status") && metaKeys.includes("revised"),
    `metadata: ${metaKeys.join(",")}`);

  const seen = await poll(page, `document.body.innerText`,
    (t) => /evidence/i.test(t) && /analyst/i.test(t), 45000);
  const lower = String(seen || "").toLowerCase();
  const rendered = spans.filter((s) => lower.includes(s));
  check("the trace page renders those spans", rendered.length === spans.length,
    `${rendered.length} of ${spans.length} span names visible: ${rendered.join(",")}`);
  await still(page, "L02_langfuse_trace_stages.png");

  // The score names attached to this trace come from the trace record itself: the list
  // endpoint ignores a traceId filter, so querying it would report the whole project.
  const record = await api(`/traces/${traceId}`);
  const pushed = [...new Set((record.scores || []).map((s) => s.name))].sort();
  check("deterministic and judge scores are attached to the trace",
    pushed.includes("deterministic_validation") && pushed.includes("llm_as_judge")
      && pushed.includes("citation_grounding"),
    `${pushed.length} score names: ${pushed.join(",")}`);
  const onScreen = pushed.filter((n) => lower.includes(n.toLowerCase()));
  check("the pushed scores appear on the trace page", onScreen.length >= 3,
    `${onScreen.length} of ${pushed.length} score names on screen: ${onScreen.join(",")}`);

  // Scroll the trace itself rather than clicking a tab: the score chips already live on
  // the Preview pane, so a tab click either did nothing or navigated to the Scores page.
  const scrolled = await scrollMain(page, 900);
  await sleep(1200);
  const detail = await page.text();
  const gens = (detail.match(/GENERATION/g) || []).length;
  check("the trace page scrolls to the model calls", scrolled > 0 && gens >= 4,
    `scrollTop ${scrolled}, ${gens} GENERATION rows visible`);
  await still(page, "L03_langfuse_trace_generations.png");

  await page.navigate(`${BASE}/project/${pid}/scores`);
  await widenRange(page, "all time");
  const srows = await poll(page, `document.querySelectorAll("table tbody tr").length`, (n) => n >= 3, 45000);
  check("the scores table lists recorded scores", srows >= 3, `${srows} score rows on screen`);
  const open = await page.js(`(() => {
    const items = [...document.querySelectorAll("[role='option'],[role='menuitem'],button")]
      .filter(e => (e.innerText || "").trim() === "30 min" && e.offsetParent !== null);
    return items.length;
  })()`);
  check("the range popover is closed before the shot", open === 0, `${open} menu items still visible`);
  await still(page, "L04_langfuse_scores_table.png");

  await page.navigate(`${BASE}/project/${pid}`);
  await sleep(4000);
  // The dashboard opens on the same 24-hour window, and on that window every card reads
  // zero. Without widening it the closing shot would contradict the traces the list page
  // just showed. Its picker is a different component from the table's and has no "All
  // time" entry — the longest option it offers is "1 year" — so the count is read back
  // off the page rather than assumed.
  await widenRange(page, "1 year");
  const dash = await poll(page, `document.body.innerText`, (t) => {
    const m = String(t || "").match(/([\d,]+)\s+Total traces tracked/i);
    return m && m[1] !== "0";
  }, 45000);
  const tracesCell = (String(dash || "").match(/([\d,]+)\s+Total traces tracked/i) || [])[1];
  const scoresCell = (String(dash || "").match(/([\d,]+)\s+Total scores tracked/i) || [])[1];
  check("the project dashboard counts the recorded work", !!tracesCell && tracesCell !== "0",
    `dashboard shows ${tracesCell} traces, ${scoresCell} scores`);
  // The API is the authority, but the two sides count different things: the card joins
  // each score to its trace, while the raw score list counts every row. Comparing them
  // directly would compare 907 against 931 and call the difference a bug in the page.
  const allScores = [];
  for (let p = 1; p <= 15; p++) {
    const j = await api(`/scores?limit=100&page=${p}`);
    allScores.push(...(j.data || []));
    if (!j.data || j.data.length < 100) break;
  }
  const allTraceIds = new Set();
  for (let p = 1; p <= 5; p++) {
    const j = await api(`/traces?limit=100&page=${p}`);
    for (const t of (j.data || [])) allTraceIds.add(t.id);
    if (!j.data || j.data.length < 100) break;
  }
  const orphans = allScores.filter((s) => !allTraceIds.has(s.traceId));
  const orphanIds = [...new Set(orphans.map((s) => s.traceId))];
  const attached = allScores.length - orphans.length;
  const num = (s) => parseInt(String(s || "").replace(/,/g, ""), 10);
  check("the dashboard cards match the store they read",
    num(tracesCell) === allTraceIds.size && num(scoresCell) === attached,
    `cards ${tracesCell}/${scoresCell} vs ${allTraceIds.size} traces and ${attached} score rows on a listed trace`);
  check("every score row belongs to a listed trace", orphans.length === 0,
    `${orphans.length} orphan rows on ${orphanIds.length} missing trace ids: ${orphanIds.join(",")}`);
  await still(page, "L05_langfuse_dashboard.png");

  clearInterval(timer);
  const pass = results.filter((r) => r.status === "PASS").length;
  const fail = results.length - pass;
  writeResult("langfuse_results.json", {
    results, pass, fail, project: pid, sampler_frames: seq,
    trace_id_shown: traceId, trace_shown_at: wanted.timestamp,
    trace_shown_cve: (wanted.metadata || {}).cve_id,
    api_total_traces: allTraceIds.size, api_total_scores: allScores.length,
    orphan_score_rows: orphans.length, orphan_trace_ids: orphanIds,
    dashboard_trace_card: tracesCell || null, dashboard_score_card: scoresCell || null,
    score_names_on_shown_trace: pushed || [], spans_on_shown_trace: spans || [],
  });
  appendFileSync(SUMMARY, `LANGFUSE DONE pass=${pass} fail=${fail} sampler_frames=${seq}\n`);
  log(`LANGFUSE DONE pass=${pass} fail=${fail} sampler_frames=${seq}`);
  chrome.kill();
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { log("FATAL", String(e).slice(0, 400)); process.exit(2); });
