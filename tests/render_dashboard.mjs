// Renders the dashboard and checks it. Needs Node + Playwright (`npm i -g playwright && npx playwright install chromium`).
//
//   node tests/render_dashboard.mjs                 sample mode (file://): every view at 1280 and 390 px, no JS errors,
//                                                   no horizontal overflow, sample score red 20 / blue 81, and
//                                                   JS score() == cc/scoring.py on shared fixtures (parity)
//   node tests/render_dashboard.mjs --live URL      also against a running cc/server.py: badge LIVE, KPIs == the API,
//                                                   score == /api/score, every feed timestamp parsed
// Always: starts its own cc/server.py on a spare loopback port with a WRONG indexer password and checks the dashboard
// says "LIVE · DEGRADED" with the error and empty panels, never sample data (v3 silently fell back to SAMPLE).
//
// Screenshots go to a temp dir (printed). Exit code 1 on any failure.
import { createRequire } from "module";
import { execFileSync, spawn } from "child_process";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DASH = pathToFileURL(path.join(ROOT, "cc", "dashboard.html")).href;
const OUT = mkdtempSync(path.join(tmpdir(), "cc-shots-"));
const VIEWS = ["command", "red", "blue", "purple", "white", "green"];
const liveArg = process.argv.indexOf("--live");
const LIVE = liveArg > 0 ? process.argv[liveArg + 1] : null;
let failures = 0;
const check = (ok, msg) => { console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`); if (!ok) failures++; };

function pyScore(steps, triage) {
  const code = "import json,sys; sys.path.insert(0,'cc'); import scoring as S; d=json.load(sys.stdin); " +
    "print(json.dumps({'s': S.score(d['steps'], d['triage']), 'rubric': S.RUBRIC}))";
  return JSON.parse(execFileSync("python3", ["-I", "-c", code], { cwd: ROOT, input: JSON.stringify({ steps, triage }) }));
}

async function renderAll(browser, url, tag) {
  for (const [w, h, dev] of [[1280, 900, "d"], [390, 844, "m"]]) {
    const page = await browser.newPage({ viewport: { width: w, height: h } });
    const errs = [];
    page.on("pageerror", (e) => errs.push(String(e)));
    page.on("console", (m) => m.type() === "error" && errs.push(m.text()));
    await page.goto(url);
    await page.waitForFunction(() => document.getElementById("mode").textContent !== "—", null, { timeout: 15000 });
    for (const v of VIEWS) {
      await page.evaluate((x) => { location.hash = x; }, v);
      await page.waitForTimeout(150);
      await page.screenshot({ path: `${OUT}/${tag}_${dev}_${v}.png`, fullPage: dev === "d" });
    }
    const sw = await page.evaluate(() => document.documentElement.scrollWidth);
    check(errs.length === 0, `${tag} ${w}px: no JS errors ${errs.length ? JSON.stringify(errs) : ""}`);
    check(sw <= w, `${tag} ${w}px: no horizontal overflow (scrollWidth ${sw})`);
    if (dev === "d") await page.close(); else return page;   // keep the phone page for further checks
  }
}

const browser = await chromium.launch();
try {
  // ---------- sample mode ----------
  const page = await renderAll(browser, DASH, "sample");
  check(await page.evaluate(() => document.getElementById("mode").textContent) === "SAMPLE", "sample: badge SAMPLE");
  const sc = await page.evaluate(() => [document.getElementById("w_red").textContent, document.getElementById("w_blue").textContent]);
  check(sc[0] === "20" && sc[1] === "81", `sample: score red/blue ${sc} (hand-calculated 20/81)`);

  // ---------- parity: JS score() vs cc/scoring.py ----------
  const smp = await page.evaluate(() => { const s = window.__cc.sample(60); return { steps: s.purple.steps, triage: s.triage }; });
  const st = (o) => ({ src_ip: "172.30.0.10", detected: true, latency_s: 10, technique_match: true, ...o });
  const fixtures = [
    ["sample drill", smp.steps, smp.triage],
    ["empty", [], []],
    ["all evaded", [st({ detected: false, latency_s: null }), st({ detected: false, latency_s: null, technique_match: false })], []],
    ["slow + boundary latencies", [st({ latency_s: 60 }), st({ latency_s: 61 }), st({ latency_s: 300 }), st({ latency_s: 301 }), st({ latency_s: null })], []],
    ["triage mix incl. non-attacker source", [st({})], [{ src_ip: "172.30.0.10", verdict: "false_positive" },
      { src_ip: "172.30.0.10", verdict: "true_positive" }, { src_ip: "192.168.1.5", verdict: "false_positive" },
      { src_ip: "172.30.0.10", verdict: "needs_human" }]],
  ];
  const jsRubric = await page.evaluate(() => window.__cc.RUBRIC);
  for (const [name, steps, triage] of fixtures) {
    const js = await page.evaluate(([a, b]) => window.__cc.score(a, b), [steps, triage]);
    const py = pyScore(steps, triage);
    check(JSON.stringify(js.rows) === JSON.stringify(py.s.rows) && js.red === py.s.red && js.blue === py.s.blue,
      `parity '${name}': JS ${js.red}/${js.blue} == Python ${py.s.red}/${py.s.blue}`);
    if (name === "empty") check(JSON.stringify(jsRubric) === JSON.stringify(py.rubric), "parity: RUBRIC identical in JS and cc/scoring.py");
  }
  await page.close();

  // ---------- degraded: API reachable, indexer failing ----------
  const port = 18000 + Math.floor(Math.random() * 1000);
  const srv = spawn("python3", ["cc/server.py"], { cwd: ROOT, stdio: "ignore",
    env: { ...process.env, CC_BIND: "127.0.0.1", CC_PORT: String(port), INDEXER_PASS: "deliberately-wrong-for-test" } });
  try {
    const url = `http://127.0.0.1:${port}/`;
    for (let i = 0; i < 50; i++) { try { await fetch(url + "api/health"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
    const dp = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const derrs = [];
    dp.on("pageerror", (e) => derrs.push(String(e)));
    await dp.goto(url);
    await dp.waitForFunction(() => document.getElementById("mode").textContent !== "—", null, { timeout: 15000 });
    const dg = await dp.evaluate(() => ({
      mode: document.getElementById("mode").textContent, sampleShown: !document.getElementById("sampleNote").hidden,
      err: document.getElementById("errBox").hidden ? "" : document.getElementById("errBox").textContent,
      total: document.getElementById("c_total").textContent }));
    check(dg.mode === "LIVE · DEGRADED" && !dg.sampleShown, `degraded: badge '${dg.mode}', sample banner ${dg.sampleShown ? "SHOWN" : "hidden"}`);
    check(dg.err.includes("summary") && dg.total === "0", `degraded: error shown ('${dg.err.slice(0, 60)}'), total ${dg.total}, no synthetic data`);
    check(derrs.length === 0, `degraded: no JS errors ${derrs.length ? JSON.stringify(derrs) : ""}`);
    // outage after the page was served: must say so and stay off sample data (v3 switched to SAMPLE for good)
    srv.kill();
    await new Promise((r) => setTimeout(r, 500));
    await dp.click("#refresh");
    await dp.waitForFunction(() => document.getElementById("mode").textContent === "API UNREACHABLE", null, { timeout: 15000 }).catch(() => {});
    const out = await dp.evaluate(() => ({ mode: document.getElementById("mode").textContent,
      sampleShown: !document.getElementById("sampleNote").hidden, total: document.getElementById("c_total").textContent }));
    check(out.mode === "API UNREACHABLE" && !out.sampleShown && out.total === "0",
      `outage: badge '${out.mode}', sample banner ${out.sampleShown ? "SHOWN" : "hidden"}, total ${out.total}`);
    await dp.close();
  } finally {
    srv.kill();
  }

  // ---------- live mode ----------
  if (LIVE) {
    const lp = await renderAll(browser, LIVE, "live");
    const get = async (p) => (await fetch(new URL(p, LIVE))).json();
    const minutes = await lp.evaluate(() => +document.getElementById("win").value);
    const [sum, score] = [await get(`/api/summary?minutes=${minutes}`), await get(`/api/score?minutes=${Math.max(minutes, 240)}`)];
    const ui = await lp.evaluate(() => ({
      mode: document.getElementById("mode").textContent,
      total: document.getElementById("c_total").textContent.replace(/[^\d]/g, ""),
      red: document.getElementById("w_red").textContent, blue: document.getElementById("w_blue").textContent,
      badTimes: [...document.querySelectorAll("#c_feed tr td:first-child")].filter((td) => td.textContent === "—").length,
      rows: document.querySelectorAll("#c_feed tr").length,
    }));
    check(ui.mode === "LIVE", `live: badge ${ui.mode}`);
    // the API caches for 5 s and the page fetched first, so allow the total to have grown
    check(+ui.total <= sum.total && +ui.total >= sum.total - 50, `live: KPI total ${ui.total} vs API ${sum.total}`);
    check(ui.red === String(score.red) && ui.blue === String(score.blue), `live: score ${ui.red}/${ui.blue} == /api/score ${score.red}/${score.blue}`);
    check(ui.rows > 0 && ui.badTimes === 0, `live: ${ui.rows} feed rows, ${ui.badTimes} unparsed timestamps`);
    await lp.close();
  }
} finally {
  await browser.close();
}
console.log(`screenshots in ${OUT}`);
console.log(failures ? `RENDER: ${failures} FAILED` : "RENDER: ALL PASS");
process.exit(failures ? 1 : 0);
