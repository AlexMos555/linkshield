/**
 * What the smoke test does in Firefox, step by step, as a person would.
 *
 * Every step gets the same context: `s` (the WebDriver session), `base`
 * (the add-on's moz-extension://<uuid>/), `lang` (of the demo pages the stub
 * serves), `check(name, ok, detail)`,
 * `shot(file, png)`, `until(fn)` (retry until fn returns something without
 * `pending`/`error`) and `sleep(ms)`. Two windows: the first shows the web
 * pages; the second holds Settings, from where the open popup is read
 * (browser.extension.getViews) without taking focus from the first.
 */
import { clickToolbarButton, closePopup, popupPng } from "./geckodriver.mjs";
import { EXPECTED, HOSTS, URLS, pageFor } from "../store-screenshots/fixtures.mjs";

export const ADDON_ID = "cleanway@cleanway.ai";

/** Install; the background opens the welcome tab, where a person says who uses the browser. */
export async function installAndWelcome(ctx, addonPath, tabA, canary) {
  const { s, base, check, until } = ctx;
  const id = await s.installTemporaryAddon(addonPath);
  check("installed as a temporary add-on", id === ADDON_ID, id);
  const welcome = await until(async () => {
    for (const h of await s.handles()) {
      if (h === tabA) continue;
      await s.switchTo(h);
      if ((await s.url()).startsWith(`${base}src/popup/welcome.html`)) return { handle: h };
    }
    return { pending: true };
  }, 20000, 500);
  // Its picture is taken at the end: in the first seconds after Firefox
  // starts, its font list is still loading, and the page's 🛡 (U+1F6E1) is
  // drawn as a box with the code in it — on any page, the add-on's or not.
  check("the background started: the welcome tab opened", welcome && welcome.handle,
    welcome && !welcome.handle ? JSON.stringify(welcome) : "");
  if (!welcome || !welcome.handle) return null;
  await until(() => s.content(`return document.readyState === "complete" ? {} : { pending: true };`));
  await s.content(`document.querySelector('.persona-card[data-skill="pro"]').click(); return true;`);
  const picked = await until(() => s.content(`return browser.storage.local.get("skill_level")
    .then((d) => (d.skill_level === "pro" ? d : { pending: true, got: d.skill_level || null }));`));
  check("the welcome page saves who uses the browser", picked && picked.skill_level === "pro", JSON.stringify(picked));
  await canary();
  return welcome.handle;
}

/** The link marks on the search page: green, yellow, red, as the offline rules say. */
export async function linkMarks(ctx) {
  const { s, check, shot, until, lang } = ctx;
  // The links of the page the stub serves, in order: each must be found and
  // marked (an empty or short list must not pass as "every link").
  const served = [...pageFor(URLS.search, lang).matchAll(/<a href="([^"]+)"/g)].map((m) => new URL(m[1]).hostname);
  const sameLinks = (got) => got.length === served.length && got.every(([host], i) => host === served[i]);
  await s.go(URLS.search);
  const marks = await until(async () => {
    const got = await s.content(`return [...document.querySelectorAll("main a")].map((a) => {
      const b = a.nextElementSibling;
      const level = b && b.classList.contains("ls-badge") ?
        (["safe", "caution", "dangerous"].find((l) => b.classList.contains("ls-" + l)) || "other") : null;
      return [new URL(a.href).hostname, level];
    });`);
    return sameLinks(got) && got.every(([, level]) => level) ? got : { pending: true, got };
  });
  const list = Array.isArray(marks) ? marks : (marks && marks.got) || [];
  const wrong = list.filter(([host, level]) => level !== (EXPECTED[host] || "safe"));
  check("content scripts mark every link with its verdict",
    served.length > 0 && Array.isArray(marks) && sameLinks(list) && wrong.length === 0,
    `${list.map(([h, l]) => `${h} ${l}`).join(", ") || (marks && marks.error) || "no links found"}` +
    `${sameLinks(list) ? "" : ` — the page has ${served.length}: ${served.join(", ")}`}`);
  shot("01-link-badges.png", await s.screenshot());
}

/** Settings in the second window: account row, the level from the welcome page, webmail switch. */
export async function settings(ctx) {
  const { s, base, check, shot, until, sleep } = ctx;
  await s.go(`${base}src/options/options.html`);
  const got = await until(() => s.content(`
    const $ = (id) => document.getElementById(id);
    if (document.readyState !== "complete" || $("account-section").hidden) return { pending: true };
    return { account: $("account-label").textContent.trim(),
      level: (document.querySelector('input[name="skill-level"]:checked') || {}).value || null,
      levelOptions: !$("skill-opt-font").hidden,
      webmailOff: $("webmail-scanner").disabled, webmailStatus: $("webmail-status").hidden ? "" : $("webmail-status").textContent };`));
  check("Settings loads: the background answers the account row", got && got.account, got ? `"${got.account}"` : "no answer");
  check("Settings shows the protection level picked on the welcome page", got && got.level === "pro" && got.levelOptions,
    got ? `${got.level}${got.levelOptions ? ", with its text-size option" : ""}` : "");
  check("Settings: the webmail switch is available in Firefox", got && got.webmailOff === false, got ? got.webmailStatus : "");
  // Back to Regular, as a person would: the rest of the run is in that mode.
  await s.content(`document.querySelector('input[name="skill-level"][value="regular"]').click(); return true;`);
  const saved = await until(() => s.content(`return browser.storage.local.get("skill_level")
    .then((d) => (d.skill_level === "regular" ? d : { pending: true, got: d.skill_level || null }));`));
  check("Settings saves a new protection level", saved && saved.skill_level === "regular", JSON.stringify(saved));
  await sleep(500);
  shot("05-settings.png", await s.screenshot());
}

/**
 * Click the toolbar button over the first window's tab (its address starts
 * with `tabUrl`), read the popup's verdict once it stops "Checking this
 * page…", picture it, close it. Called with the second window current.
 */
export async function popup(ctx, file, tabUrl, expectState, host) {
  const { s, check, shot, until, sleep, popupHeights } = ctx;
  await clickToolbarButton(s, ADDON_ID, tabUrl);
  const read = `const v = (browser.extension.getViews({ type: "popup" }) || [])[0];
    if (!v) return { pending: true, why: "no popup page" };
    const d = v.document, $ = (id) => d.getElementById(id), card = $("status-card");
    if (d.readyState !== "complete" || !card || card.dataset.state === "scanning") return { pending: true, state: card && card.dataset.state };
    return { state: card.dataset.state, title: $("status-title").textContent.trim(), sub: $("status-subtitle").textContent.trim(),
      offline: !$("offline-banner").hidden, height: d.documentElement.scrollHeight };`;
  let ui = await until(() => s.content(read));
  if (ui && !ui.pending && !ui.error) {
    await sleep(1200); // the popup's own /health check and the account row
    ui = await s.content(read);
  }
  check(`popup on ${host}: ${expectState}`, ui && ui.state === expectState && ui.sub.includes(host) && !ui.offline,
    ui && ui.state ? `${ui.state} — ${ui.title} — ${ui.sub}${ui.offline ? " — OFFLINE banner" : ""}` : JSON.stringify(ui));
  // Firefox, like Chrome, shows at most 600 px of a popup; the rest scrolls.
  if (ui && ui.height) popupHeights[file] = ui.height;
  if (ui && ui.state && ui.state !== "scanning") shot(file, await popupPng(s, ADDON_ID, tabUrl));
  await closePopup(s, ADDON_ID, tabUrl);
}

/**
 * The popup's buttons over the recipe page ("What this site collects", "My
 * week", and "My safety level" under "More"): each is a message from the
 * popup to the tab's content script, which opens its panel on the page.
 */
export async function popupButtons(ctx, tabA, second) {
  const { s, check, until, sleep } = ctx;
  const panels = { "btn-audit": "ls-audit-result", "btn-week": "ls-weekly-report", "btn-score": "ls-score-overlay" };
  const got = [];
  for (const [button, panel] of Object.entries(panels)) {
    await s.switchTo(second);
    await closePopup(s, ADDON_ID, URLS.recipe); // the button toggles: start from a closed popup
    await clickToolbarButton(s, ADDON_ID, URLS.recipe);
    const clicked = await until(() => s.content(`const v = (browser.extension.getViews({ type: "popup" }) || [])[0];
      const d = v && v.document;
      if (!d || d.readyState !== "complete") return { pending: true };
      const b = d.getElementById(${JSON.stringify(button)}), more = b && b.closest("details");
      if (more && !more.open) more.querySelector("summary").click();
      b.click();
      return { clicked: true };`));
    await s.switchTo(tabA);
    const shown = clicked && clicked.clicked &&
      await until(() => s.content(`return document.getElementById(${JSON.stringify(panel)}) ? {} : { pending: true };`), 8000);
    got.push(`${button.slice(4)} ${shown && !shown.pending && !shown.error ? "opened" : "MISSING"}`);
    await s.go(URLS.recipe); // a clean page for the next button
    await sleep(1000);
  }
  check("the popup's buttons open their panels on the page", got.every((g) => g.endsWith("opened")), got.join(", "));
}

/** Wait for the block page in the current tab, with "open anyway" past its countdown. */
async function blockPage(ctx) {
  const { s, base, until } = ctx;
  return until(async () => {
    const url = await s.url();
    if (!url.startsWith(`${base}src/blocked/blocked.html?`)) return { pending: true, url };
    const r = await s.content(`const o = document.getElementById("ls-block-overlay");
      if (!o) return { pending: true };
      const p = document.getElementById("ls-block-proceed");
      return { url: location.href, domain: o.querySelector(".ls-block-domain").textContent.trim(), proceedReady: !!p && !p.disabled };`);
    return r.pending || r.proceedReady ? r : { ...r, pending: true };
  }, 30000, 300);
}

/** Opening the scam page in the first window: the tab is taken to the block page. */
export async function scamIsBlocked(ctx) {
  const { s, base, check, shot, sleep } = ctx;
  await s.go(URLS.scam).catch(() => {}); // the page is left before it finishes loading
  const blocked = await blockPage(ctx);
  check("the scam page is replaced by the block page", blocked && blocked.url?.startsWith(`${base}src/blocked/blocked.html?`),
    (blocked && blocked.url) || JSON.stringify(blocked));
  check("the block page names the site", blocked && blocked.domain === HOSTS.scam, blocked && blocked.domain);
  check("\"open anyway\" is enabled after the countdown", blocked && blocked.proceedReady === true);
  await sleep(600);
  shot("04-block-page.png", await s.screenshot());
}

/** The block page's two buttons, in the first window. */
export async function blockButtons(ctx) {
  const { s, base, check, until, sleep } = ctx;
  // "Go back to safety": the page before the scam one.
  await s.content(`document.getElementById("ls-block-back").click(); return true;`);
  const back = await until(async () => {
    const url = await s.url();
    return url.startsWith(base) || url.includes(HOSTS.scam) ? { pending: true, url } : { url };
  }, 15000, 300);
  check("\"Go back to safety\" returns to the page before the scam", back && back.url === URLS.caution, back && back.url);
  // "Open anyway": the site loads again in this tab, and stays.
  await s.go(URLS.scam).catch(() => {});
  const ready = await blockPage(ctx);
  if (ready && ready.proceedReady) await s.content(`document.getElementById("ls-block-proceed").click(); return true;`);
  const opened = await until(async () => {
    const url = await s.url();
    return url === URLS.scam ? { url } : { pending: true, url };
  }, 15000, 300);
  await sleep(3000); // long enough for a second block to come
  const now = await s.url();
  check("\"Open anyway\" opens the site and it stays open", ready && ready.proceedReady && opened && opened.url && now === URLS.scam,
    `${ready && ready.proceedReady ? "clicked" : "the button never became ready"}; now on ${now}`);
}

/** The block-page sample, src/popup/block-preview.html. */
export async function blockPreview(ctx) {
  const { s, base, check, shot, until, sleep } = ctx;
  await s.go(`${base}src/popup/block-preview.html`);
  const got = await until(() => s.content(`const o = document.getElementById("ls-block-overlay");
    return o ? { domain: o.querySelector(".ls-block-domain").textContent.trim() } : { pending: true };`));
  check("the block-page sample renders", got && got.domain, got && got.domain);
  await sleep(600);
  shot("06-block-preview.png", await s.screenshot());
}

/** Settings again: the counters the background kept during the run. */
export async function statistics(ctx) {
  const { s, base, check, until } = ctx;
  await s.go(`${base}src/options/options.html`);
  const n = await until(() => s.content(`const n = (id) => Number(document.getElementById(id).textContent);
    return n("s-total") > 0 ? { total: n("s-total"), blocked: n("s-blocked"), warned: n("s-warned") } : { pending: true };`));
  check("Settings shows the background's statistics", n && n.total > 0 && n.blocked >= 1 && n.warned >= 1,
    n && n.total ? `checked ${n.total}, blocked ${n.blocked}, warnings ${n.warned}` : JSON.stringify(n));
}
