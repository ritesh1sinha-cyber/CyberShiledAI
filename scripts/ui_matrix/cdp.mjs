// Minimal local CDP driver: no third-party packages, Node built-ins only.
import { spawn } from "node:child_process";
import { writeFileSync, appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The Chrome binary and the scratch directory are machine-local; override them with
// KGP_CHROME and KGP_CAPTURE_DIR. The frames this writes are capture artefacts and stay
// out of the repository; the manifest, the log and the summary are committed next to it.
const CHROME = process.env.KGP_CHROME || "c:/Program Files/Google/Chrome/Application/chrome.exe";
const PORT = 9333;
export const OUT = process.env.KGP_CAPTURE_DIR || "C:/Users/IN009287/AppData/Local/Temp/kgp_cdp";
const PROFILE = join(OUT, "profile");
export const FRAMES = join(OUT, "frames");
mkdirSync(FRAMES, { recursive: true });
mkdirSync(PROFILE, { recursive: true });

export const LOG = join(OUT, "matrix.log");
export const MANIFEST = join(OUT, "frames.jsonl");

export function log(...parts) {
  const line = `[${new Date().toISOString()}] ${parts.join(" ")}`;
  console.log(line);
  appendFileSync(LOG, line + "\n");
}

async function httpJson(pathname) {
  const res = await fetch(`http://127.0.0.1:${PORT}${pathname}`);
  return res.json();
}

export async function launchChrome(profileDir) {
  const dir = profileDir || PROFILE;
  const p = spawn(CHROME, [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${dir}`,
    "--window-size=1440,1100",
    "--hide-scrollbars",
    "about:blank",
  ], { stdio: "ignore" });
  p.on("exit", (code) => log("chrome exited", code));
  for (let i = 0; i < 60; i++) {
    try {
      const v = await httpJson("/json/version");
      log("chrome ready", v.Browser);
      return p;
    } catch {
      await sleep(500);
    }
  }
  throw new Error("chrome did not start");
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Page {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    this.ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      } else {
        for (const l of this.listeners) l(msg);
      }
    });
  }
  static async open(urlFragment) {
    const targets = await httpJson("/json/list");
    const t = targets.find((x) => x.type === "page" && (!urlFragment || x.url.includes(urlFragment)))
      || targets.find((x) => x.type === "page");
    const ws = new WebSocket(t.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      ws.addEventListener("open", res, { once: true });
      ws.addEventListener("error", () => rej(new Error("ws error")), { once: true });
    });
    const pg = new Page(ws);
    await pg.send("Page.enable");
    await pg.send("Runtime.enable");
    await pg.send("DOM.enable");
    await pg.send("Emulation.setDeviceMetricsOverride", {
      width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false,
    });
    return pg;
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`timeout: ${method}`));
        }
      }, 120000);
    });
  }
  on(fn) { this.listeners.push(fn); }
  async navigate(url) {
    await this.send("Page.navigate", { url });
    await sleep(1500);
  }
  async js(expression, awaitPromise = true) {
    const r = await this.send("Runtime.evaluate", {
      expression, awaitPromise, returnByValue: true, userGesture: true,
    });
    if (r.exceptionDetails) {
      throw new Error("JS: " + (r.exceptionDetails.exception?.description || JSON.stringify(r.exceptionDetails)).slice(0, 500));
    }
    return r.result.value;
  }
  async text() {
    return this.js(`document.body.innerText`);
  }
  async waitForText(sub, timeoutMs = 90000, intervalMs = 1000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const t = await this.text();
      if (t && t.includes(sub)) return true;
      await sleep(intervalMs);
    }
    return false;
  }
  // Click the first element whose trimmed text equals/matches `needle` (css: selector to scope).
  async clickText(needle, selector = "button, [role='button'], a, label") {
    const box = await this.js(`(() => {
      const els = [...document.querySelectorAll(${JSON.stringify(selector)})];
      const el = els.find(e => (e.innerText || e.textContent || '').trim().includes(${JSON.stringify(needle)}));
      if (!el) return null;
      el.scrollIntoView({block: 'center', inline: 'center'});
      const r = el.getBoundingClientRect();
      return {x: r.x + r.width / 2, y: r.y + r.height / 2, label: el.innerText.trim().slice(0, 80)};
    })()`);
    if (!box) throw new Error("clickText: not found: " + needle);
    await sleep(250);
    for (const type of ["mousePressed", "mouseReleased"]) {
      await this.send("Input.dispatchMouseEvent", {
        type, x: Math.round(box.x), y: Math.round(box.y),
        button: "left", clickCount: 1,
      });
      if (type === "mouseReleased") await sleep(60);
    }
    return box.label;
  }
  // Focus a textarea by aria-label/placeholder substring, then type like a user.
  async typeInto(value, match = "") {
    const ok = await this.js(`(() => {
      const tas = [...document.querySelectorAll('textarea')];
      const el = ${match ? `tas.find(e => (e.getAttribute('aria-label')||e.getAttribute('placeholder')||'').includes(${JSON.stringify(match)}))` : "tas[0]"};
      if (!el) return false;
      el.scrollIntoView({block: 'center'});
      el.focus();
      const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
      set.call(el, '');
      el.dispatchEvent(new Event('input', {bubbles: true}));
      return true;
    })()`);
    if (!ok) throw new Error("typeInto: textarea not found (" + match + ")");
    await this.send("Input.insertText", { text: value });
    await sleep(600);
    // Streamlit text_area commits on blur; a synthetic Enter would submit the form early.
    await this.js(`(() => { const el = document.activeElement; if (el && el.blur) el.blur(); return true; })()`);
    await sleep(1500);
  }
  async press(key) {
    const code = { Enter: "Enter", Escape: "Escape", Tab: "Tab", ArrowDown: "ArrowDown" }[key] || key;
    for (const type of ["keyDown", "keyUp"]) {
      await this.send("Input.dispatchKeyEvent", {
        type, key, code, windowsVirtualKeyCode: code === "Enter" ? 13 : 0, nativeVirtualKeyCode: code === "Enter" ? 13 : 0,
      });
    }
  }
  async setScrollTop(px) {
    await this.js(`(() => { const s = document.querySelector('section.main') || document.scrollingElement; s.scrollTop = ${px}; return s.scrollTop; })()`);
  }
  async scrollBy(dy) {
    return this.js(`(() => {
      const s = document.querySelector('section.main') || document.scrollingElement;
      s.scrollTop += ${dy};
      return {top: Math.round(s.scrollTop), max: Math.round(s.scrollHeight), h: Math.round(s.clientHeight)};
    })()`);
  }
  async pageHeight() {
    return this.js(`(() => { const s = document.querySelector('section.main') || document.scrollingElement; return {top: s.scrollTop, max: s.scrollHeight, h: s.clientHeight}; })()`);
  }
  async screenshot(file) {
    const r = await this.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(file, Buffer.from(r.data, "base64"));
    return file;
  }
}

// Continuous sampler: 1 fps capture, tagged with the current scenario label.
export class Sampler {
  constructor(page) {
    this.page = page;
    this.seq = 0;
    this.label = "unlabelled";
    this.timer = null;
    this.periodMs = 1000;
  }
  start(label) {
    this.label = label;
    if (this.timer) return;
    this.timer = setInterval(async () => {
      try {
        this.seq += 1;
        const name = `frame_${String(this.seq).padStart(4, "0")}.png`;
        const path = join(FRAMES, name);
        await this.page.screenshot(path);
        appendFileSync(MANIFEST, JSON.stringify({
          n: this.seq, file: name, label: this.label, at: new Date().toISOString(),
        }) + "\n");
      } catch (e) {
        log("sampler error", String(e).slice(0, 160));
      }
    }, this.periodMs);
  }
  setLabel(label) { this.label = label; }
  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

export function writeResult(name, obj) {
  writeFileSync(join(OUT, name), JSON.stringify(obj, null, 2));
}
