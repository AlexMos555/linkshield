# Store Listing — Cleanway (Android)

> **Honesty contract.** Every claim here is grounded in what the code actually
> does (verified egress: the app contacts only `api.cleanway.ai` + `cleanway.ai`,
> plus Sentry for crash logs and Supabase for optional account/family). No
> hardcoded recall/AUC — detection numbers live and dated at
> **cleanway.ai/transparency/methodology**. The shield uses Android's VpnService
> **locally** to filter DNS on-device; it is **not** an anonymity/proxy VPN and
> routes no traffic to a remote server. RU is the primary market (Tele2 launch),
> so the Russian copy is authoritative; English follows for the Play/global listing.

---

## 🇷🇺 Русский (основной)

### Название
Cleanway — защита от фишинга

### Короткое описание (до 80 символов)
Блокирует фишинговые и мошеннические сайты. Проверка ссылок на устройстве.

### Полное описание
Cleanway защищает от фишинга и сайтов-подделок — тех самых ссылок, что приходят
в СМС «ваша посылка», «заблокирована карта», «вы выиграли».

ЧТО ДЕЛАЕТ:
• Сетевой щит блокирует известные фишинговые сайты автоматически — на всём
  телефоне, в любом браузере и приложении, ещё до того как страница откроется.
• Проверка любой ссылки: вставьте адрес, отсканируйте QR-код или поделитесь
  ссылкой из другого приложения — Cleanway скажет, безопасно ли это.
• Если сайт опасный, вы получаете понятное уведомление на русском: что это за
  угроза и почему.

КАК УСТРОЕНА ЗАЩИТА (честно):
Cleanway использует системный VPN-механизм Android, но **не как VPN для
анонимности**. Никакой ваш трафик не уходит на наши или чужие серверы, IP не
скрывается и не подменяется. Список опасных доменов хранится прямо на телефоне,
и совпадение проверяется локально — поэтому блокировка мгновенная и работает
даже без интернета. Только для новой, ещё неизвестной ссылки телефон
спрашивает наш сервер — и отправляет **лишь имя домена** (например `example.com`),
не полный адрес и не содержимое страницы.

ПРИВАТНОСТЬ:
• История ваших проверок хранится на устройстве.
• На сервер уходит только имя домена для проверки — не полный URL, не содержимое.
• Мы не продаём данные и не показываем рекламу.
• Аккаунт и «Семья» — по желанию; без них приложение полностью работает.
• Данные передаются по шифрованному соединению (TLS). Удалить свои данные можно
  в приложении или по запросу на support@cleanway.ai.

Базовая защита — бесплатно.

Актуальные, датированные измерения качества детекта:
cleanway.ai/transparency/methodology

### Что нового (v1.0.0)
Первый публичный выпуск:
• Сетевой щит — блокировка известных фишинговых доменов на устройстве
• Проверка ссылок: вставка, QR-код, «Поделиться»
• Понятные уведомления об угрозах на русском языке

---

## 🇬🇧 English (global / Play)

### Name
Cleanway — Phishing Protection

### Short description (80 chars)
Blocks phishing & scam sites. Link checking that runs on your device.

### Full description
Cleanway protects you from phishing and fake sites — the links that arrive by
SMS: "your parcel is waiting", "your card is blocked", "you won a prize".

WHAT IT DOES:
• The network shield blocks known phishing sites automatically — across the
  whole phone, in any browser or app, before the page can load.
• Check any link: paste a URL, scan a QR code, or share a link from another
  app, and Cleanway tells you whether it's safe.
• If a site is dangerous you get a clear notification explaining the threat.

HOW THE PROTECTION WORKS (honestly):
Cleanway uses Android's VPN mechanism **locally** — it is **not an anonymity
VPN**. None of your traffic is sent to our servers or anyone else's, and your
IP is never hidden or changed. The list of dangerous domains lives on your
phone and is matched on-device, so blocking is instant and works even offline.
Only for a new, not-yet-known link does the phone ask our server — sending
**only the domain name** (e.g. `example.com`), never the full URL or page content.

PRIVACY:
• Your check history stays on your device.
• Only the domain name is sent for a safety check — never the full URL or content.
• We don't sell data and show no ads.
• An account and Family sharing are optional; the app works fully without them.
• Data travels over encrypted (TLS) connections. Delete your data in the app or
  by emailing support@cleanway.ai.

Core protection is free.

Live, dated detection measurements: cleanway.ai/transparency/methodology

### What's New (v1.0.0)
First public release:
• Network shield — on-device blocking of known phishing domains
• Link checking: paste, QR scan, Share sheet
• Clear, localized threat notifications

---

## Metadata (both stores)

| Field | Value |
|---|---|
| Category | Tools / Security (RuStore: Инструменты / Безопасность) |
| Content rating | Everyone / 0+ |
| Privacy policy | https://cleanway.ai/privacy-policy |
| Support | https://cleanway.ai/support · support@cleanway.ai |
| Website | https://cleanway.ai |

### Removed vs. the old draft (and why)
- ❌ "YOUR DATA STAYS ON YOUR DEVICE / even if breached your data is safe" —
  false: domain names are sent to the server for checks. Replaced with the
  accurate domain-only statement.
- ❌ "93.5% recall / AUC 0.95" hardcoded — the honest live figure is lower and
  moves; point to /transparency/methodology instead.
- ❌ "VPN Protection" as a feature name — reframed as an on-device DNS filter
  with an explicit "not an anonymity VPN" statement (RF-critical + honest).
- ❌ Breach Check headline, Privacy Audit, Weekly Report, Security Score, and
  the $4.99/$9.99 tiers — omitted from v1 launch copy: not all are verified
  working on mobile (store IAP not wired), and a listing must not promise them.
  Re-add each only once it's shipped and paid delivery works on-store.
