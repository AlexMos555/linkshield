"""Cultural scam-explainer — Strategy doc Top-20 #15.

Generates a 2-3 sentence "here's why this looks dangerous" message
that's grammatically native AND culturally specific to the user's
locale. Default Norton/Bitdefender/McAfee surfaces ship machine-
translated boilerplate that references US payment patterns (Venmo,
Zelle) on a Brazilian or Indonesian user's screen. We do better:

  * Russian readers see references to Авито / Госуслуги / СберБанк
  * Spanish-speakers in Mexico see references to OXXO and SAT
  * Portuguese-speakers (Brazil) see references to PIX and Bradesco
  * Hindi-speakers see references to UPI and NPCI
  * etc.

The cultural payload comes from a hand-curated mapping below.
When the upstream LLM key arrives we replace the deterministic
combiner with a Claude / GPT call — the function signature stays
identical, so call-sites don't change.

Architecture:

  explain_scam(verdict, signals, locale) →
    1. Pick the dominant scam category (credential phishing,
       package-delivery scam, bank impostor, crypto drainer,
       generic suspicious) from the signal set.
    2. Look up the locale-specific BAIT_REFERENCES for that
       category — local brand names, payment systems, agencies.
    3. If ANTHROPIC_API_KEY is set, call Claude with a prompt
       that combines (a) category, (b) cultural references,
       (c) the actual signals that fired. Otherwise emit a
       deterministic template message in the requested locale.
    4. Cache the result by sha256(category + sorted(signals) +
       locale) for 7 days — explanations for the same scam
       pattern don't change every day.

Privacy:
  * The signal SET is what we cache by, NOT the domain or URL.
  * We never log the user's domain in the explainer path.
  * LLM calls send the category + signal list ONLY — the actual
    domain stays on the request path that called us, not in the
    LLM payload.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────────
# Category taxonomy — five buckets that map clearly to the kind
# of cultural reference a user would understand instantly.
# ───────────────────────────────────────────────────────────────

CATEGORIES = (
    "credential_phishing",
    "package_delivery_scam",
    "bank_impostor",
    "crypto_drainer",
    "generic_suspicious",
)

# Heuristic: which signals from scoring.py imply which category.
# Order matters — first match wins, so put the more specific
# categories ahead of the catch-alls.
_CATEGORY_RULES: tuple[tuple[str, frozenset[str]], ...] = (
    ("credential_phishing", frozenset({
        "credential_form_mismatch", "favicon_brand_clone",
        "typosquat_brand_match", "homograph_attack",
        "phishtank", "safe_browsing",
    })),
    ("crypto_drainer", frozenset({
        "metamask_brand", "phantom_brand", "wallet_drain_pattern",
        "binance_brand",  # combined with off-brand favicon → drainer
    })),
    ("bank_impostor", frozenset({
        "chase_brand", "wellsfargo_brand", "hsbc_brand",
        "santander_brand", "barclays_brand", "bankofamerica_brand",
    })),
    ("package_delivery_scam", frozenset({
        "dhl_brand", "ups_brand", "fedex_brand",
        "package_pickup_pattern", "shipping_fee_request",
    })),
)


def categorise(signals: Iterable[str]) -> str:
    """Pick the dominant category for a given signal set.

    Falls back to 'generic_suspicious' if nothing matched — that
    bucket still gets a localised message, just less specific.
    """
    sigs = set(signals or ())
    for category, members in _CATEGORY_RULES:
        if sigs & members:
            return category
    return "generic_suspicious"


# ───────────────────────────────────────────────────────────────
# Cultural references per locale × category. Curated by hand —
# the names here are the FIRST thing a native reader would think
# of, not a Wikipedia roll-call. When you add a brand, ask: "if I
# said this to a regular person on the street in <country>, would
# they nod or look at me funny?". The latter means drop it.
# ───────────────────────────────────────────────────────────────

LOCALES = ("en", "es", "hi", "pt", "ru", "ar", "fr", "de", "it", "id")

# Per-locale phrase fragments. Each (locale, category) entry
# contains:
#   - bait: nouns / brand names the scam typically targets
#   - action: the verb of the harm (your money, your account, etc.)
#   - safe_action: what the user should do instead
_CULTURAL: dict[str, dict[str, dict[str, str]]] = {
    "en": {
        "credential_phishing": {
            "bait": "your bank or email password",
            "action": "the criminals running this page will use it within minutes to drain accounts",
            "safe_action": "type the company's address into a new tab instead of clicking links",
        },
        "package_delivery_scam": {
            "bait": "a fake DHL/UPS/FedEx tracking notice",
            "action": "asks for a small \"customs fee\" by card — the real charge then runs to thousands",
            "safe_action": "log into your carrier account directly to see real shipments",
        },
        "bank_impostor": {
            "bait": "a clone of your bank's login page",
            "action": "harvests credentials + 2FA codes in real time and empties accounts",
            "safe_action": "open the bank app on your phone, never click bank links from email",
        },
        "crypto_drainer": {
            "bait": "a fake MetaMask / wallet-approval dialog",
            "action": "drains every token from your wallet in a single approve() call",
            "safe_action": "disconnect this site from your wallet immediately; never approve unlimited spend",
        },
        "generic_suspicious": {
            "bait": "personal or payment details",
            "action": "passes them to criminals",
            "safe_action": "leave the page and reach the real company through their official app or known URL",
        },
    },
    "ru": {
        "credential_phishing": {
            "bait": "пароли от Госуслуг, СберБанка или электронной почты",
            "action": "мошенники используют их в первые минуты — выводят деньги, оформляют кредиты на ваше имя",
            "safe_action": "наберите адрес банка вручную в новой вкладке, а не идите по ссылке из СМС",
        },
        "package_delivery_scam": {
            "bait": "поддельный трек СДЭК / Почты России / Boxberry",
            "action": "требует «таможенный сбор» картой — настоящие списания вырастают в десятки тысяч",
            "safe_action": "проверьте трек только через официальное приложение перевозчика",
        },
        "bank_impostor": {
            "bait": "копия страницы входа Тинькофф, Сбера или Альфа",
            "action": "ворует пароль и код из СМС в режиме реального времени и тут же опустошает счёт",
            "safe_action": "откройте приложение банка на телефоне; никогда не входите в банк по ссылке из почты",
        },
        "crypto_drainer": {
            "bait": "фальшивое окно одобрения транзакции в MetaMask",
            "action": "одним approve() выводит все токены кошелька",
            "safe_action": "отключите этот сайт от кошелька; никогда не разрешайте «безлимитную» трату",
        },
        "generic_suspicious": {
            "bait": "личные или платёжные данные",
            "action": "передаст их злоумышленникам",
            "safe_action": "закройте страницу и зайдите в нужный сервис через официальное приложение",
        },
    },
    "es": {
        "credential_phishing": {
            "bait": "contraseñas de tu banco, BBVA o Santander",
            "action": "los estafadores las usan en minutos para vaciar cuentas o pedir créditos a tu nombre",
            "safe_action": "abre la web del banco escribiendo la dirección a mano, no por enlaces",
        },
        "package_delivery_scam": {
            "bait": "un aviso falso de Correos / DHL / FedEx",
            "action": "pide una «comisión de aduana» con tarjeta — luego los cargos suben a cientos",
            "safe_action": "entra a la cuenta de la mensajería directamente para ver envíos reales",
        },
        "bank_impostor": {
            "bait": "una copia de la página de tu banco (BBVA, CaixaBank, Santander)",
            "action": "captura usuario, contraseña y SMS de 2FA en tiempo real",
            "safe_action": "usa la app oficial del banco; nunca abras enlaces a tu banco desde email",
        },
        "crypto_drainer": {
            "bait": "un cuadro falso de aprobación de MetaMask",
            "action": "drena cada token de tu billetera con una sola firma approve()",
            "safe_action": "desconecta este sitio de tu wallet; nunca apruebes gasto ilimitado",
        },
        "generic_suspicious": {
            "bait": "datos personales o de pago",
            "action": "los entrega a delincuentes",
            "safe_action": "cierra la página y entra al servicio real por la app oficial",
        },
    },
    "pt": {
        "credential_phishing": {
            "bait": "senha do banco (Bradesco, Itaú, Caixa) ou do PIX",
            "action": "os criminosos usam em minutos para esvaziar contas via PIX",
            "safe_action": "digite o endereço do banco direto no navegador; nunca pelo link do SMS",
        },
        "package_delivery_scam": {
            "bait": "aviso falso dos Correios / da Receita Federal",
            "action": "pede taxa de \"liberação alfândega\" no cartão — o cobrança real chega a centenas",
            "safe_action": "entre no site dos Correios pelo app oficial para ver a remessa real",
        },
        "bank_impostor": {
            "bait": "uma cópia da página de login do seu banco",
            "action": "captura senha + código de 2FA em tempo real",
            "safe_action": "abra o app do banco no celular; nunca pelo link do email",
        },
        "crypto_drainer": {
            "bait": "uma falsa janela approve() do MetaMask",
            "action": "drena todos os tokens da carteira com uma única assinatura",
            "safe_action": "desconecte esta página da carteira; nunca aprove gasto ilimitado",
        },
        "generic_suspicious": {
            "bait": "dados pessoais ou de pagamento",
            "action": "vai entregá-los a criminosos",
            "safe_action": "feche a página e entre pelo aplicativo oficial",
        },
    },
    "hi": {
        "credential_phishing": {
            "bait": "आपका बैंक पासवर्ड या UPI PIN",
            "action": "ठग कुछ ही मिनटों में UPI से पैसे निकाल लेते हैं",
            "safe_action": "बैंक का पता खुद टाइप करके खोलें; SMS के लिंक से कभी न जाएँ",
        },
        "package_delivery_scam": {
            "bait": "नकली India Post / DHL डिलीवरी सूचना",
            "action": "\"कस्टम ड्यूटी\" के नाम पर कार्ड पर शुल्क लेता है, फिर बड़ी रकम काट लेता है",
            "safe_action": "केवल ऑफिशियल ऐप में जाकर शिपमेंट देखें",
        },
        "bank_impostor": {
            "bait": "SBI / HDFC / ICICI लॉगिन पेज की नकली कॉपी",
            "action": "पासवर्ड और OTP को रियल-टाइम में चुराकर खाता खाली कर देते हैं",
            "safe_action": "अपने फोन में बैंक ऐप खोलें; ईमेल लिंक से कभी लॉगिन न करें",
        },
        "crypto_drainer": {
            "bait": "नकली MetaMask approve() डायलॉग",
            "action": "एक ही सिग्नेचर में पूरा वॉलेट खाली कर देता है",
            "safe_action": "वॉलेट से इस साइट को तुरंत डिस्कनेक्ट करें",
        },
        "generic_suspicious": {
            "bait": "व्यक्तिगत या भुगतान विवरण",
            "action": "उन्हें अपराधियों को सौंप देगा",
            "safe_action": "पेज बंद करें और ऑफिशियल ऐप से जाएँ",
        },
    },
    "ar": {
        "credential_phishing": {
            "bait": "كلمات مرور البنك أو البريد",
            "action": "يستخدمها المحتالون خلال دقائق لسحب الأموال",
            "safe_action": "اكتب عنوان البنك يدوياً، ولا تستخدم رابط الرسالة",
        },
        "package_delivery_scam": {
            "bait": "إشعار شحنة مزيف من DHL/Aramex/SMSA",
            "action": "يطلب \"رسوم جمركية\" على البطاقة، ثم يخصم مبالغ كبيرة",
            "safe_action": "افتح تطبيق الشحن الرسمي مباشرة",
        },
        "bank_impostor": {
            "bait": "نسخة من صفحة دخول مصرفك",
            "action": "تسرق كلمة المرور ورمز 2FA في الوقت الفعلي",
            "safe_action": "افتح تطبيق المصرف على الهاتف، ولا تدخل من رابط البريد",
        },
        "crypto_drainer": {
            "bait": "نافذة approve() مزيفة لـ MetaMask",
            "action": "تسحب كل العملات من المحفظة بتوقيع واحد",
            "safe_action": "افصل هذا الموقع من المحفظة فوراً",
        },
        "generic_suspicious": {
            "bait": "بيانات شخصية أو دفع",
            "action": "ستسلمها إلى مجرمين",
            "safe_action": "أغلق الصفحة وادخل عبر التطبيق الرسمي",
        },
    },
    "fr": {
        "credential_phishing": {
            "bait": "vos identifiants Crédit Agricole, BNP ou La Poste",
            "action": "les escrocs vident le compte en quelques minutes",
            "safe_action": "tapez l'adresse de la banque directement dans le navigateur",
        },
        "package_delivery_scam": {
            "bait": "un faux suivi La Poste / Chronopost / DHL",
            "action": "demande des « frais de douane » par carte, puis prélève des centaines d'euros",
            "safe_action": "vérifiez via l'app officielle du transporteur",
        },
        "bank_impostor": {
            "bait": "une copie de la page de connexion de votre banque",
            "action": "capture identifiant et code SMS en temps réel",
            "safe_action": "ouvrez l'app de la banque sur le téléphone; jamais un lien d'email",
        },
        "crypto_drainer": {
            "bait": "une fausse fenêtre approve() de MetaMask",
            "action": "vide chaque token du portefeuille en une seule signature",
            "safe_action": "déconnectez ce site du wallet immédiatement",
        },
        "generic_suspicious": {
            "bait": "vos données personnelles ou bancaires",
            "action": "les remettra à des criminels",
            "safe_action": "fermez la page et passez par l'app officielle",
        },
    },
    "de": {
        "credential_phishing": {
            "bait": "Zugangsdaten zu Sparkasse, Volksbank oder DKB",
            "action": "Betrüger räumen das Konto innerhalb von Minuten leer",
            "safe_action": "geben Sie die Bank-Adresse selbst im Browser ein, nicht aus einer E-Mail",
        },
        "package_delivery_scam": {
            "bait": "gefälschte DHL/Hermes/DPD-Zustellbenachrichtigung",
            "action": "fordert „Zollgebühren\" per Karte, danach folgen dreistellige Abbuchungen",
            "safe_action": "öffnen Sie das offizielle Versand-Konto direkt in der App",
        },
        "bank_impostor": {
            "bait": "eine Kopie Ihrer Bank-Anmeldeseite",
            "action": "stiehlt Passwort und 2FA-Code in Echtzeit",
            "safe_action": "nutzen Sie die offizielle Bank-App; nie einen Link aus E-Mail anklicken",
        },
        "crypto_drainer": {
            "bait": "ein gefälschter MetaMask-approve()-Dialog",
            "action": "leert die Wallet mit einer einzigen Signatur",
            "safe_action": "trennen Sie diese Seite sofort von der Wallet",
        },
        "generic_suspicious": {
            "bait": "persönliche oder Zahlungsdaten",
            "action": "übergibt sie Kriminellen",
            "safe_action": "schließen Sie die Seite und nutzen Sie die offizielle App",
        },
    },
    "it": {
        "credential_phishing": {
            "bait": "le credenziali di Intesa Sanpaolo, Poste o UniCredit",
            "action": "i truffatori svuotano il conto in pochi minuti",
            "safe_action": "digiti l'indirizzo della banca a mano, mai dal link di un SMS",
        },
        "package_delivery_scam": {
            "bait": "un finto avviso Poste Italiane / SDA / DHL",
            "action": "chiede « spese doganali » con carta, poi sottrae cifre a tre zeri",
            "safe_action": "verifichi solo dall'app ufficiale del corriere",
        },
        "bank_impostor": {
            "bait": "copia della pagina di accesso della sua banca",
            "action": "ruba password e OTP in tempo reale",
            "safe_action": "apra l'app della banca sul telefono; mai dal link email",
        },
        "crypto_drainer": {
            "bait": "una falsa finestra approve() di MetaMask",
            "action": "svuota ogni token del wallet con una sola firma",
            "safe_action": "disconnetta subito questo sito dal wallet",
        },
        "generic_suspicious": {
            "bait": "dati personali o di pagamento",
            "action": "li consegnerà ai criminali",
            "safe_action": "chiuda la pagina e usi l'app ufficiale",
        },
    },
    "id": {
        "credential_phishing": {
            "bait": "kata sandi BCA, Mandiri, atau OVO",
            "action": "penipu menguras saldo dalam hitungan menit lewat transfer real-time",
            "safe_action": "ketik alamat bank di tab baru, jangan klik dari SMS",
        },
        "package_delivery_scam": {
            "bait": "pemberitahuan palsu JNE / Pos Indonesia / DHL",
            "action": "meminta \"biaya bea cukai\" di kartu, lalu menarik ratusan ribu",
            "safe_action": "cek pengiriman lewat aplikasi resmi kurir",
        },
        "bank_impostor": {
            "bait": "salinan halaman login bank Anda",
            "action": "mencuri password + kode OTP secara real-time",
            "safe_action": "buka aplikasi bank di ponsel; jangan klik link email",
        },
        "crypto_drainer": {
            "bait": "dialog approve() MetaMask palsu",
            "action": "menguras seluruh token dompet dengan satu tanda tangan",
            "safe_action": "putuskan situs ini dari dompet sekarang juga",
        },
        "generic_suspicious": {
            "bait": "data pribadi atau pembayaran",
            "action": "akan menyerahkannya ke pelaku kejahatan",
            "safe_action": "tutup halaman dan masuk lewat aplikasi resmi",
        },
    },
}


def _cache_key(category: str, signals: Iterable[str], locale: str) -> str:
    """Stable key that doesn't include the domain — so the same
    pattern across many domains hits the same cache entry."""
    payload = json.dumps({
        "category": category,
        "signals": sorted(set(signals or ())),
        "locale": locale,
    }, sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"explainer:v1:{digest}"


def _deterministic_explanation(category: str, locale: str) -> str:
    """Template fallback — used when the LLM key isn't provisioned
    OR when the LLM call fails. Three sentences: what the page is
    after, what the criminals do with it, what the user should do."""
    loc = _CULTURAL.get(locale) or _CULTURAL["en"]
    cat = loc.get(category) or loc["generic_suspicious"]
    # Sentence template per locale would be more polished; we pick
    # a punctuation set that reads correctly in CJK + RTL too.
    return (
        f"{cat['bait']} — {cat['action']}. "
        f"{cat['safe_action']}."
    )


def _llm_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


async def _llm_explanation(
    category: str, signals: Iterable[str], locale: str,
) -> Optional[str]:
    """Call Claude when the key is provisioned. Returns the LLM's
    string, or None on any error so the caller falls back to the
    deterministic template.

    The system prompt is locked to "produce 2-3 sentences, native
    register, cite the cultural reference exactly". We send the
    cultural payload as a hint so the model doesn't invent
    inappropriate brands.
    """
    if not _llm_available():
        return None
    try:
        # Late import — `anthropic` is an optional dependency. If
        # it's not installed we just fall back. This is also a
        # safety net for the SBOM: tests don't need the package.
        import anthropic  # type: ignore
    except ImportError:
        return None

    loc = _CULTURAL.get(locale) or _CULTURAL["en"]
    cat_hints = loc.get(category) or loc["generic_suspicious"]

    sys_prompt = (
        "You write 2-3 SHORT sentences explaining why a flagged "
        "page is dangerous, in the user's native language. NEVER "
        "invent foreign brand names — only use the brands in the "
        "cultural-hints payload. Output ONLY the explanation, no "
        "preamble. Total length under 320 characters."
    )
    user_payload = json.dumps({
        "category": category,
        "locale": locale,
        "signals_that_fired": sorted(set(signals or ())),
        "cultural_hints": cat_hints,
    }, ensure_ascii=False)

    try:
        # AsyncAnthropic + await — the sync client's .create() is a blocking
        # network call and would freeze the single event loop for every
        # concurrent request while one explanation waited. (2026-07-04 audit.)
        client = anthropic.AsyncAnthropic()
        # Model is deliberately small/cheap — explanations don't
        # need a flagship model.
        resp = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            system=sys_prompt,
            messages=[{"role": "user", "content": user_payload}],
        )
        # Extract the text block.
        for block in resp.content:
            if getattr(block, "type", None) == "text":
                text = (block.text or "").strip()
                if text:
                    return text[:600]  # hard cap
    except Exception as exc:
        logger.warning("LLM explainer call failed, falling back: %s", exc)
    return None


async def explain_scam(
    signals: Iterable[str], locale: str = "en",
) -> dict:
    """Return a culturally-aware explanation of why a page is dangerous.

    Returns:
        {
          "category": str,
          "locale": str,
          "explanation": str,
          "source": "llm" | "template",
        }

    Never raises. Always returns a usable explanation.
    """
    locale = (locale or "en").lower()
    if locale not in LOCALES:
        locale = "en"
    signals_set = set(signals or ())

    category = categorise(signals_set)

    # L1: Redis cache (transparent — failures fall through).
    cache_key = _cache_key(category, signals_set, locale)
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        cached = await r.get(cache_key)
        if cached:
            return {
                "category": category,
                "locale": locale,
                "explanation": cached,
                "source": "cache",
            }
    except Exception:
        r = None  # cache outage — proceed without

    # L2: LLM when available. Catch every exception here — a
    # crashing LLM client (network, auth, schema mismatch on the
    # SDK release) must NEVER take down the explainer endpoint.
    # The user always gets a usable answer, even if it's the
    # deterministic template.
    try:
        explanation = await _llm_explanation(category, signals_set, locale)
    except Exception as exc:
        logger.warning("LLM explainer crashed, falling back: %s", exc)
        explanation = None
    source = "llm" if explanation else "template"
    if explanation is None:
        explanation = _deterministic_explanation(category, locale)

    # Cache for 7 days so repeated identical signal-sets don't
    # re-bill the LLM.
    if r is not None:
        try:
            await r.setex(cache_key, 7 * 24 * 3600, explanation)
        except Exception:
            pass

    return {
        "category": category,
        "locale": locale,
        "explanation": explanation,
        "source": source,
    }
