// ── Inline i18n with fallback ──
    const WELCOME_EN = {
      welcome_hero_title: "You're protected now",
      welcome_hero_subtitle: "Every link you see is being checked. Dangerous ones will be blocked automatically.",
      welcome_step1_title: "Automatic scanning",
      welcome_step1_desc: "Every page, every link. Green badge means safe. Red means scam.",
      welcome_step2_title: "Your data stays with you",
      welcome_step2_desc: "We only check domain names. Your browsing history never leaves this device.",
      welcome_step3_title: "No slowdown",
      welcome_step3_desc: "Most checks happen on your device in under a second. Just browse normally.",
      welcome_step4_title: "For the whole family",
      welcome_step4_desc: "Protect parents, kids, grandparents with one plan. Different modes for each.",
      welcome_cta_scan: "\uD83D\uDCE7 Scan my inbox for hidden scams",
      welcome_cta_skip: "Skip — start browsing",
      welcome_trust_footer: "Free forever for blocking. Your data never leaves this device.",
      welcome_persona_title: "Who mostly uses this device?",
      welcome_persona_regular: "Me — regular",
      welcome_persona_granny: "A parent / grandparent",
      welcome_persona_kids: "A child",
      welcome_persona_pro: "A pro / power user",
      welcome_persona_hint: "Tunes how warnings are explained. Change any time in Settings.",
    };

    // Preview / standalone: optional overrides per language
    const PREVIEW_LANGS = {
      ru: {
        welcome_hero_title: "Вы под защитой",
        welcome_hero_subtitle: "Каждая ссылка, которую вы видите, проверяется. Опасные блокируются автоматически.",
        welcome_step1_title: "Автоматическая проверка",
        welcome_step1_desc: "Каждая страница, каждая ссылка. Зелёная отметка — безопасно. Красная — мошенники.",
        welcome_step2_title: "Ваши данные остаются с вами",
        welcome_step2_desc: "Мы проверяем только названия сайтов. История посещений никогда не покидает это устройство.",
        welcome_step3_title: "Без тормозов",
        welcome_step3_desc: "Большинство проверок происходит прямо на вашем устройстве за долю секунды.",
        welcome_step4_title: "Для всей семьи",
        welcome_step4_desc: "Защитите родителей, детей, бабушек одной подпиской. Разные режимы для каждого.",
        welcome_cta_scan: "\uD83D\uDCE7 Проверить мою почту на мошенников",
        welcome_cta_skip: "Пропустить — начать пользоваться",
        welcome_trust_footer: "Блокировка бесплатна навсегда. Ваши данные не покидают это устройство.",
      },
      es: {
        welcome_hero_title: "Ya estás protegido",
        welcome_hero_subtitle: "Cada enlace que ves se revisa. Los peligrosos se bloquean automáticamente.",
        welcome_step1_title: "Revisión automática",
        welcome_step1_desc: "Cada página, cada enlace. Etiqueta verde: seguro. Roja: estafa.",
        welcome_step2_title: "Tus datos se quedan contigo",
        welcome_step2_desc: "Solo revisamos nombres de sitios. Tu historial nunca sale de este dispositivo.",
        welcome_step3_title: "Sin ralentizar",
        welcome_step3_desc: "La mayoría de revisiones ocurren en tu dispositivo en menos de un segundo.",
        welcome_step4_title: "Para toda la familia",
        welcome_step4_desc: "Protege a padres, hijos y abuelos con un solo plan. Modos distintos para cada uno.",
        welcome_cta_scan: "\uD83D\uDCE7 Revisar mi bandeja por estafas ocultas",
        welcome_cta_skip: "Saltar — empezar a navegar",
        welcome_trust_footer: "El bloqueo siempre es gratis. Tus datos nunca salen de este dispositivo.",
      },
      ar: {
        welcome_hero_title: "أنت محمي الآن",
        welcome_hero_subtitle: "يتم فحص كل رابط تراه. الروابط الخطرة تُحظر تلقائيًا.",
        welcome_step1_title: "فحص تلقائي",
        welcome_step1_desc: "كل صفحة، كل رابط. العلامة الخضراء: آمن. الحمراء: احتيال.",
        welcome_step2_title: "بياناتك تبقى معك",
        welcome_step2_desc: "نفحص أسماء المواقع فقط. سجل تصفّحك لا يغادر هذا الجهاز أبدًا.",
        welcome_step3_title: "دون تباطؤ",
        welcome_step3_desc: "تتم معظم الفحوصات على جهازك في أقل من ثانية.",
        welcome_step4_title: "للعائلة بأكملها",
        welcome_step4_desc: "احمِ الوالدين والأطفال والأجداد بخطة واحدة. أوضاع مختلفة للجميع.",
        welcome_cta_scan: "\uD83D\uDCE7 افحص بريدي بحثًا عن احتيال مخفي",
        welcome_cta_skip: "تخطَّ — ابدأ التصفح",
        welcome_trust_footer: "الحظر مجاني دائمًا. بياناتك لا تغادر هذا الجهاز أبدًا.",
      },
    };

    function currentLang() {
      const sel = document.getElementById("lang-selector");
      if (sel && sel.value && sel.value !== "auto") return sel.value;
      try {
        if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getUILanguage) {
          return chrome.i18n.getUILanguage().split("-")[0];
        }
      } catch (_) {}
      return (navigator.language || "en").split("-")[0];
    }

    function translate(key) {
      // 1. Try chrome.i18n (real extension context)
      try {
        if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getMessage) {
          const sel = document.getElementById("lang-selector");
          // Only use chrome.i18n if user selected auto; otherwise use PREVIEW_LANGS for live switch
          if (!sel || sel.value === "auto") {
            const msg = chrome.i18n.getMessage(key);
            if (msg) return msg;
          }
        }
      } catch (_) {}
      // 2. Manual language override for preview
      const lang = currentLang();
      if (PREVIEW_LANGS[lang] && PREVIEW_LANGS[lang][key]) return PREVIEW_LANGS[lang][key];
      // 3. English fallback
      return WELCOME_EN[key] || key;
    }

    function applyI18n() {
      document.querySelectorAll("[data-i18n]").forEach((el) => {
        const key = el.getAttribute("data-i18n");
        const msg = translate(key);
        if (msg) el.textContent = msg;
      });
      // Set document dir for RTL languages
      document.documentElement.dir = (currentLang() === "ar") ? "rtl" : "ltr";
      document.documentElement.lang = currentLang();
    }

    // Skip button — close this tab (or noop if can't)
    document.getElementById("cta-skip").addEventListener("click", () => {
      try {
        if (typeof chrome !== "undefined" && chrome.tabs) {
          chrome.tabs.getCurrent((tab) => {
            if (tab) chrome.tabs.remove(tab.id);
          });
        } else {
          window.close();
        }
      } catch (_) { window.close(); }
    });

    // Language selector — live preview
    const sel = document.getElementById("lang-selector");
    if (sel) {
      sel.addEventListener("change", applyI18n);
    }

    // Persona picker — write skill_level to chrome.storage.local so the
    // block page + popup persona modes (regular/granny/kids/pro) pick it up.
    // Reflect the currently-stored choice on load; default "regular".
    (function initPersona() {
      const cards = Array.from(document.querySelectorAll(".persona-card"));
      if (!cards.length) return;
      function select(skill) {
        cards.forEach((c) => c.setAttribute("aria-pressed", String(c.dataset.skill === skill)));
      }
      cards.forEach((card) => {
        card.addEventListener("click", () => {
          const skill = card.dataset.skill || "regular";
          select(skill);
          try {
            if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
              chrome.storage.local.set({ skill_level: skill });
            }
          } catch (_) { /* storage unavailable — selection is still shown */ }
        });
      });
      try {
        if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
          chrome.storage.local.get(["skill_level"], (data) => {
            select((data && data.skill_level) || "regular");
          });
        }
      } catch (_) { /* keep the default regular selection */ }
    })();

    // Initial render
    applyI18n();
