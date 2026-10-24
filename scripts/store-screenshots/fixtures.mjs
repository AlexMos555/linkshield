/**
 * The demo pages the store screenshots are taken on, in English and Russian.
 *
 * Every host is made up: reserved .example names for the ordinary sites, and
 * scam-shaped names on .xyz/.top for the bad ones. None imitates a real brand
 * (the only real site is Wikipedia, as a link in the search results and the
 * recipe, never as a page we serve). The script serves these pages itself;
 * nothing is fetched from the internet.
 *
 * EXPECTED is what the extension's own offline rules (src/utils/local-scorer.js)
 * must say about each host. extension.mjs checks it before every run, so a
 * change to the rules cannot silently turn a shot into something else.
 */

export const HOSTS = {
  search: "search.example",
  recipes: "recipes.example",
  help: "help.parcel-service.example",
  scam: "parcel-redelivery-payment-verify.xyz",
  caution: "redelivery-payment-confirm.top",
  tracking: "track-parcel-update.xyz",
};

export const EXPECTED = {
  [HOSTS.search]: "safe",
  [HOSTS.recipes]: "safe",
  [HOSTS.help]: "safe",
  [HOSTS.scam]: "dangerous",
  [HOSTS.caution]: "caution",
  [HOSTS.tracking]: "caution",
};

/** Where each host shows up, for the README. */
export const WHERE = {
  [HOSTS.search]: "04 (the page)",
  [HOSTS.recipes]: "02 (the page)",
  [HOSTS.help]: "04 (green badge)",
  [HOSTS.scam]: "01 (blocked), 04 (red badge)",
  [HOSTS.caution]: "03 (the page), 04 (yellow badge)",
  [HOSTS.tracking]: "04 (yellow badge)",
};

export const URLS = {
  search: `https://${HOSTS.search}/search`,
  recipe: `https://${HOSTS.recipes}/sourdough`,
  caution: `https://${HOSTS.caution}/confirm`,
  scam: `https://${HOSTS.scam}/pay`,
};

const TEXT = {
  en: {
    query: "parcel redelivery fee",
    searchButton: "Search",
    results: [
      ["Phishing — Wikipedia", "en.wikipedia.org", "https://en.wikipedia.org/wiki/Phishing", "wiki › Phishing",
        "Messages that pretend to come from a bank, a shop or a delivery company and ask for a password or a card number."],
      ["Missed a delivery? Rebook it for free", HOSTS.help, `https://${HOSTS.help}/redelivery`, "redelivery",
        "Pick a new day or a pickup point. Rebooking is free, and we never ask for a fee by text message."],
      ["Your parcel is on hold — pay the redelivery fee within 24 hours", HOSTS.scam, `https://${HOSTS.scam}/pay`, "pay",
        "Pay a small fee to release your parcel. Unpaid parcels are returned to the sender."],
      ["Confirm the redelivery of your parcel", HOSTS.caution, `https://${HOSTS.caution}/confirm`, "confirm",
        "Confirm your address and payment details to book a new delivery."],
      ["Parcel status updates", HOSTS.tracking, `https://${HOSTS.tracking}/`, "",
        "Enter your tracking number to see where your parcel is now."],
    ],
    recipeTitle: "Sunday sourdough: your first loaf",
    recipeBody: [
      "All you need is flour, water, salt and an active starter. If the word is new to you, " +
        "start with the <a href=\"https://en.wikipedia.org/wiki/Sourdough\">article on sourdough</a>.",
      "Mix the flour and water and leave them for an hour. Add the starter and the salt, " +
        "fold the dough every half hour for two hours, then let it rise overnight in the fridge.",
      "Bake at 240 °C in a covered pot for 20 minutes, then uncovered until the crust is deep brown. " +
        "Want a darker loaf? Swap a fifth of the flour for <a href=\"https://en.wikipedia.org/wiki/Rye_bread\">rye</a>.",
    ],
    recipeList: ["You need", "500 g strong white flour", "350 g water", "100 g active starter", "10 g salt"],
    recipeMethod: "Method",
    recipeAside: "Next week: a quick focaccia.",
    cautionTitle: "Parcel redelivery",
    cautionBody: "We tried to deliver your parcel, but nobody was home. Confirm your address and pay the redelivery fee to book a new delivery.",
    cautionNote: "Your parcel will be kept for 3 days.",
    cautionButton: "Continue",
    scamTitle: "Your parcel is on hold",
    scamBody: "Pay the redelivery fee to release your parcel.",
    scamButton: "Pay now",
  },
  ru: {
    query: "оплата повторной доставки посылки",
    searchButton: "Найти",
    results: [
      ["Фишинг — Википедия", "ru.wikipedia.org", "https://ru.wikipedia.org/wiki/Фишинг", "wiki › Фишинг",
        "Письма и сообщения, которые притворяются банком, магазином или службой доставки и просят пароль или номер карты."],
      ["Не застали курьера? Перенос бесплатный", HOSTS.help, `https://${HOSTS.help}/redelivery`, "redelivery",
        "Выберите новый день или пункт выдачи. Перенос бесплатный, и мы никогда не просим оплату по СМС."],
      ["Посылка задержана — оплатите повторную доставку в течение 24 часов", HOSTS.scam, `https://${HOSTS.scam}/pay`, "pay",
        "Оплатите небольшой сбор, чтобы получить посылку. Неоплаченные посылки возвращаются отправителю."],
      ["Подтвердите повторную доставку посылки", HOSTS.caution, `https://${HOSTS.caution}/confirm`, "confirm",
        "Подтвердите адрес и платёжные данные, чтобы назначить новую доставку."],
      ["Статус посылки", HOSTS.tracking, `https://${HOSTS.tracking}/`, "",
        "Введите трек-номер, чтобы узнать, где сейчас ваша посылка."],
    ],
    recipeTitle: "Хлеб на закваске: первая буханка",
    recipeBody: [
      "Нужны только мука, вода, соль и активная закваска. Если слово вам незнакомо, " +
        "начните со <a href=\"https://ru.wikipedia.org/wiki/Закваска\">статьи о закваске</a>.",
      "Смешайте муку с водой и оставьте на час. Добавьте закваску и соль, " +
        "складывайте тесто каждые полчаса в течение двух часов, затем уберите на ночь в холодильник.",
      "Выпекайте при 240 °C в закрытой форме 20 минут, затем без крышки, пока корка не станет тёмной. " +
        "Хотите хлеб потемнее? Замените пятую часть муки <a href=\"https://ru.wikipedia.org/wiki/Ржаной_хлеб\">ржаной</a>.",
    ],
    recipeList: ["Понадобится", "500 г пшеничной муки", "350 г воды", "100 г активной закваски", "10 г соли"],
    recipeMethod: "Как печь",
    recipeAside: "На следующей неделе: быстрая фокачча.",
    cautionTitle: "Повторная доставка",
    cautionBody: "Мы пытались доставить вашу посылку, но никого не было дома. Подтвердите адрес и оплатите повторную доставку, чтобы назначить новую дату.",
    cautionNote: "Посылка хранится 3 дня.",
    cautionButton: "Продолжить",
    scamTitle: "Посылка задержана",
    scamBody: "Оплатите повторную доставку, чтобы получить посылку.",
    scamButton: "Оплатить",
  },
};

const BASE_CSS =
  "*{box-sizing:border-box}body{margin:0;background:#fff;color:#1f2937;" +
  "font:16px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif}" +
  "a{color:#1d4ed8;text-decoration:none}a:hover{text-decoration:underline}" +
  "button{font:inherit;border:0;border-radius:8px;padding:11px 26px;cursor:pointer}";

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

const doc = (lang, title, css, body) =>
  `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><title>${esc(title)}</title>` +
  `<style>${BASE_CSS}${css}</style></head><body>${body}</body></html>`;

function searchPage(lang) {
  const t = TEXT[lang];
  const css =
    "header{display:flex;gap:12px;align-items:center;padding:22px 120px;border-bottom:1px solid #e5e7eb;background:#f9fafb}" +
    ".box{flex:0 1 560px;padding:11px 18px;border:1px solid #d1d5db;border-radius:24px;background:#fff;color:#111827}" +
    "header button{background:#1d4ed8;color:#fff;border-radius:24px}" +
    "main{max-width:720px;margin:0 0 0 120px;padding:12px 0 40px}" +
    ".r{margin:26px 0}.crumb{font-size:13px;color:#4b5563}.crumb b{font-weight:500;color:#111827}" +
    ".r a{font-size:20px;line-height:1.35}.r p{margin:4px 0 0;color:#4b5563;font-size:15px}";
  const results = t.results.map(([title, host, href, path, snippet]) =>
    `<div class="r"><div class="crumb"><b>${esc(host)}</b>${path ? ` › ${esc(path)}` : ""}</div>` +
    `<a href="${esc(href)}">${esc(title)}</a><p>${esc(snippet)}</p></div>`).join("");
  return doc(lang, t.query, css,
    `<header><div class="box">${esc(t.query)}</div><button type="button">${esc(t.searchButton)}</button></header>` +
    `<main>${results}</main>`);
}

const ARTICLE_CSS =
  "main{max-width:640px;margin:0 0 0 96px;padding:56px 0}h1{font-size:34px;line-height:1.2;margin:0 0 22px;color:#111827}" +
  "p{margin:0 0 18px;font-size:18px}h2{font-size:21px;margin:28px 0 10px;color:#111827}ul{margin:0 0 8px;padding-left:22px;font-size:18px}" +
  "li{margin:4px 0}.aside{color:#6b7280;font-size:15px;border-top:1px solid #e5e7eb;padding-top:16px}";

function recipePage(lang) {
  const t = TEXT[lang];
  return doc(lang, t.recipeTitle, ARTICLE_CSS + "body{background:#fffdf8}",
    `<main><h1>${esc(t.recipeTitle)}</h1><p>${t.recipeBody[0]}</p>` +
    `<h2>${esc(t.recipeList[0])}</h2><ul>${t.recipeList.slice(1).map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` +
    `<h2>${esc(t.recipeMethod)}</h2>${t.recipeBody.slice(1).map((p) => `<p>${p}</p>`).join("")}` +
    `<p class="aside">${esc(t.recipeAside)}</p></main>`);
}

function noticePage(lang, title, body, note, button) {
  return doc(lang, title, ARTICLE_CSS +
    "body{background:#f3f4f6}main{background:#fff;margin-top:56px;padding:40px 44px;border-radius:14px;border:1px solid #e5e7eb}" +
    ".note{color:#6b7280;font-size:15px}main button{background:#ea580c;color:#fff;font-weight:600}",
  `<main><h1>${esc(title)}</h1><p>${esc(body)}</p>${note ? `<p class="note">${esc(note)}</p>` : ""}` +
    `<button type="button">${esc(button)}</button></main>`);
}

/** The page for a request, or null when the script does not serve that URL. */
export function pageFor(url, lang) {
  const t = TEXT[lang];
  let u;
  try { u = new URL(url); } catch (e) { return null; }
  if (u.pathname === "/favicon.ico") return null;
  switch (u.hostname) {
    case HOSTS.search: return searchPage(lang);
    case HOSTS.recipes: return recipePage(lang);
    case HOSTS.caution: return noticePage(lang, t.cautionTitle, t.cautionBody, t.cautionNote, t.cautionButton);
    case HOSTS.scam: return noticePage(lang, t.scamTitle, t.scamBody, "", t.scamButton);
    default: return null;
  }
}
