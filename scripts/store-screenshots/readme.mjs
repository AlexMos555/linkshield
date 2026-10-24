/**
 * store-assets/extension/README.md, written by extension.mjs after a run in
 * both languages, so what it says about the build, the browser, the locale
 * and every verdict is what that run actually saw.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOSTS } from "./fixtures.mjs";

export const SHOTS = [
  ["01-block-page.png",
    `The block page for \`${HOSTS.scam}\`, opened from the red search result of 04: STOP, the site's name and the ` +
    "\"Why we blocked this site\" cards for the four signs the rules found. The tab was taken to the extension's own " +
    "`src/blocked/blocked.html` when it opened that address, so the scam page never stays on screen. The page goes on " +
    "below the 800 px window (\"How scammers use sites like this\", then \"Go back to safety\" and the \"open anyway\" " +
    "button, captured after its 5-second countdown)."],
  ["02-popup-safe.png",
    `The toolbar popup on an ordinary recipe page (\`${HOSTS.recipes}\`): "This page is safe". The two Wikipedia links in the ` +
    "text carry green ticks. The welcome tip had been closed with its × button, as a person would."],
  ["03-popup-caution.png",
    `The toolbar popup on a doubtful "pay the redelivery fee" page (\`${HOSTS.caution}\`): the yellow "Some links look ` +
    "suspicious\" state. A caution verdict does not block the page. In English the second line reads \"1 links on this page " +
    "need a closer look\": that is the popup's own 0.2.2 wording, whose count is always 1 for the page itself (see " +
    "\"Upload order\")."],
  ["04-link-badges.png",
    `A search-results page (\`${HOSTS.search}\`) with a badge after every result: green ticks for Wikipedia and ` +
    `\`${HOSTS.help}\`, yellow marks for \`${HOSTS.caution}\` and \`${HOSTS.tracking}\`, a red cross for \`${HOSTS.scam}\`. ` +
    "The red badge is hovered, so its tooltip shows the first three reasons."],
  ["05-settings.png",
    "The top of the Settings page with its defaults: not signed in, the \"Who uses this browser\" choice, and email " +
    "scanning off."],
];

// Captured but kept out of one language's upload order while the popup in it
// shows `text`. 0.2.2's English caution line is built from a link count the
// background never sends (popup.js, status_warning_subtitle), so it always
// reads "1 links on this page need a closer look": true to the build, but a
// grammar slip on the listing. The run checks the popup's text, so once a
// later version fixes the wording the shot goes back into the order by itself.
export const HOLD_BACK = [
  { lang: "en", file: "03-popup-caution.png", text: /^1 links\b/,
    why: "its second line reads \"1 links on this page need a closer look\": the 0.2.2 popup builds that line from a " +
      "link count the background never sends, so it always says 1, and the English text has no singular form" },
];

/** HOLD_BACK entries that still apply to what this run's popups showed. */
export const heldBack = (locales) => HOLD_BACK.filter((h) => {
  const run = locales.find((l) => l.lang === h.lang);
  return run && h.text.test(run.popupLines[h.file] || "");
});

const code = (s) => `\`${s}\``;

function uploadOrder(locales) {
  const held = heldBack(locales);
  const rows = locales.map(({ lang }) => {
    const files = SHOTS.map(([f]) => f).filter((f) => !held.some((h) => h.lang === lang && h.file === f));
    return `| ${code(`${lang}/`)} | ${files.map(code).join(", ")} |`;
  }).join("\n");
  const notes = held.length ? [
    "The Chrome Web Store needs at least one screenshot and takes up to five, so a listing with four is complete.",
    ...held.map((h) => `**Not uploaded: ${code(`${h.lang}/${h.file}`)}.** It is true to the build, but ${h.why}. ` +
      "It stays in the folder; when a later version fixes the wording, rerun the script: it reads the popup's text and " +
      "puts the shot back into this order by itself."),
  ] : [];
  return [`| Listing | Upload, in this order |
|---------|-----------------------|
${rows}`, ...notes].join("\n\n");
}

export function writeReadme(outDir, run) {
  const verdictRows = run.verdicts.map((v) =>
    `| ${code(v.host)} | ${v.level} | ${v.reasons.length ? v.reasons.map(code).join(", ") : "none"} | ${v.where} |`).join("\n");
  const locales = run.locales.map((l) => `\`${l.lang}/\`: Chromium UI language ${code(l.uiLocale)}`).join("; ");
  const requests = run.apiPaths.map((p) => `- ${code(p)}`).join("\n");
  const refused = run.refused.length
    ? run.refused.map((u) => `- ${code(u)}`).join("\n")
    : "- none";
  const build = `${code(run.extRel)} at version ${run.version}` +
    (run.commit ? ` (last changed in commit ${code(run.commit)}${run.dirty ? ", plus local changes" : ""})` : "");
  let vsZip = "";
  if (run.zip && run.zipDiff.length === 0) {
    vsZip = ` It is byte-identical to the store package ${code(run.zip)}.`;
  } else if (run.zip) {
    const scorerOnly = run.zipDiff.every((f) => /^src\/utils\/(scorer-data|name-rules|local-scorer)\.js$/.test(f));
    vsZip = ` Compared with the store package ${code(run.zip)}, ${run.zipDiff.length === 1 ? "one file differs" : "these files differ"}: ` +
      `${run.zipDiff.map(code).join(", ")}.` +
      (scorerOnly ? " They hold the offline rules, not the interface, and the package's rules give every demo host below the same verdict." : "");
  }

  const md = `# Cleanway browser extension: store screenshots

Screenshots for the Chrome Web Store, Microsoft Edge Add-ons and Firefox AMO: 1280×800 PNG, 24-bit RGB with no alpha
channel, one set in English (\`en/\`) and one in Russian (\`ru/\`) with the same file names. Upload them in the order
given under "Upload order". They are taken in Chromium; the Edge, Firefox and Safari builds share the same
pages, styles and texts (\`packages/extension-core\`). They are made by
[\`scripts/store-screenshots/extension.mjs\`](../../scripts/store-screenshots/extension.mjs); this file is written by the
same run.

| File | What it shows |
|------|---------------|
${SHOTS.map(([file, what]) => `| \`${file}\` | ${what} |`).join("\n")}

## Upload order

${uploadOrder(run.locales)}

## What is real and what is staged

- **The extension is the real build, unmodified.** ${build}, loaded unpacked with \`--load-extension\` exactly as a person would load it.${vsZip}
- **The pages are demo pages.** The script serves the search results, the recipe and the two parcel pages itself, on made-up hosts (\`.example\` for the ordinary sites, scam-shaped \`.xyz\`/\`.top\` names for the bad ones). No real brand is imitated; Wikipedia only appears as a link.
- **Every verdict comes from the extension's own rules.** The server is replaced by a stub inside the script, as in the browser test (\`scripts/test-extension-sw.mjs\`): it answers each site check with exactly the verdict the extension's offline rules (\`src/utils/local-scorer.js\`, read from the same build) give that host, and \`GET /health\` with 200 so the popup does not show its offline banner. With no server at all the extension shows the same badges and blocks the same page, because its content script scores every host itself first. Nothing the extension shows was invented by the script: no verdict, reason, count or score. The production server, which also uses blocklists, DNS, page checks and an ML model, may say more about real sites.
- **Not shown because the stub does not answer it:** the block page's "What kind of scam is this?" paragraph (\`POST /api/v1/explain\`). Without it the block page looks exactly as in 01, which is what a person sees when that answer does not arrive. The offline rules give no confidence figure, so no confidence chip appears either. The popup's statistics stay folded under "More".
- **The popup is the real toolbar popup**, opened with the DevTools command \`Extensions.triggerAction\`, which is what clicking the toolbar icon does (it also gives the popup \`activeTab\` for that tab). Chromium draws a popup outside the page, so its picture (full height, no scrollbar: it is under Chrome's 600 px popup limit) is placed at the top right of a screenshot of the same tab. That placing is the only composition; no browser toolbar or frame is drawn.
- **Nothing left the machine.** Chromium resolved every host name to nowhere (\`--host-resolver-rules=MAP * ~NOTFOUND\`), and every request was answered or refused by the script through DevTools \`Fetch\` interception. The extension's service worker was stopped once right after start-up, as Chrome stops idle MV3 workers, so that the fresh one started inside the interception.

## How they were captured

- **Date:** ${run.date}
- **Browser:** ${run.browser} (Chromium from Playwright ${run.playwright}), new headless mode, on ${run.platform}. Viewport 1280×800 at device scale factor 1.
- **Locale:** ${locales}. The extension has no language setting of its own: it follows the browser. The script refuses to capture if the extension's \`@@ui_locale\` does not match.
- **Persona:** the default (Regular), so badges show no risk numbers.

### Verdicts at capture time

| Host | Verdict | Offline reason codes | Where |
|------|---------|----------------------|-------|
${verdictRows}

The Wikipedia hosts are on the extension's built-in list of official sites and are answered without any check.

### Server requests the stub answered (both languages)

${requests}

\`?from=screenshot-script\` is the script's own request from the restarted service worker, to prove it reaches the stub; every other line is a request the extension made.

### Requests refused (would have gone to the internet)

${refused}

## How to recapture

From the repository root, with Playwright installed in a throwaway folder (as the e2e workflow does; no repository
dependency is added):

\`\`\`sh
T="\${TMPDIR:-/tmp}/cw-shots"
npm install --prefix "$T" --no-audit --no-fund playwright@1.62.1
"$T/node_modules/.bin/playwright" install chromium     # skipped if this Chromium is already cached
NODE_PATH="$T/node_modules" node scripts/store-screenshots/extension.mjs     # en + ru, about 2 minutes
rm -rf "$T"
\`\`\`

- \`--ext <dir>\` loads another unpacked build, for example the store ZIP unzipped into a folder.
- \`en\` or \`ru\` alone retakes one language (this README is only rewritten after a run in both).
- The run fails rather than capture a wrong state: a demo host whose verdict changed (in the source tree or in the store ZIP), a missing or wrong badge, a tooltip covering another badge, a popup in the wrong state, with its offline banner or taller than 600 px, a block page that did not appear, a worker the stub cannot reach.
- On macOS, Chromium ignores \`--lang\`, so the script starts it through a two-line wrapper that adds \`-AppleLanguages (<lang>)\`. On Linux \`--lang\` and \`LANGUAGE\` are enough.
- Fonts come from the OS: the committed set was rendered on macOS; on Linux the text looks different.
`;
  writeFileSync(join(outDir, "README.md"), md);
}
