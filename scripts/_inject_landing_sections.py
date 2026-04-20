#!/usr/bin/env python3
"""
One-shot helper: inject Features/HowItWorks/PricingTeaser/Comparison/Privacy/
Testimonials/FAQ sections into packages/i18n-strings/src/{locale}.json under
the ``landing`` namespace.

Safe to rerun — it only overwrites the sections it defines and leaves other
keys untouched. After running, invoke ``python3 scripts/build-i18n.py`` to
regenerate landing/messages/*.json.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "packages" / "i18n-strings" / "src"

# Per-locale content. Keys must exist in `en` block; other locales inherit
# missing keys from en at runtime via validate_parity, but we aim for parity.
SECTIONS: dict[str, dict[str, Any]] = {
    "en": {
        "features": {
            "heading": "Everything you need. Nothing you don't.",
            "items": [
                {"icon": "🔍", "title": "Automatic Link Scanning", "desc": "Every link on every page checked against 9 threat databases. Red, yellow, green badges show safety at a glance."},
                {"icon": "🔒", "title": "Privacy Audit", "desc": "Right-click any page to see trackers, cookies, data collection, and fingerprinting. Grade A through F."},
                {"icon": "🧠", "title": "ML-Powered Detection", "desc": "CatBoost model trained on 18K+ domains. 0.9988 AUC. Catches novel phishing that rule-based systems miss."},
                {"icon": "⚡", "title": "Instant Protection", "desc": "95% of checks happen locally via bloom filter in under 1ms. No slowdown. No waiting."},
                {"icon": "📱", "title": "Your Data, Your Device", "desc": "Browsing history never touches our servers. We only see domain names. Even if breached, your data is safe."},
                {"icon": "📧", "title": "Inbox Scanner", "desc": "Finds phishing links in your Gmail and Outlook that your browser missed."},
            ],
        },
        "how_it_works": {
            "heading": "How LinkShield protects you",
            "steps": [
                {"step": "1", "title": "Install", "desc": "Add the Chrome extension. Takes 10 seconds."},
                {"step": "2", "title": "Browse", "desc": "LinkShield checks every link automatically. No action needed."},
                {"step": "3", "title": "Stay Safe", "desc": "Dangerous links get red badges. Click for details."},
            ],
        },
        "pricing_teaser": {
            "heading": "Simple, transparent pricing",
            "unit_forever": "/forever",
            "unit_month": "/month",
            "most_popular": "Most Popular",
            "trial_note": "All plans include 14-day free trial. Cancel anytime.",
            "free": {"name": "Free", "price": "$0", "features": ["10 API checks/day", "Unlimited local checks", "Privacy Audit (grade only)", "Link badges on all pages"], "cta": "Get Started"},
            "personal": {"name": "Personal", "price": "$4.99", "features": ["Unlimited checks", "Full Privacy Audit breakdown", "Weekly Security Report", "Security Score + tips", "Priority support"], "cta": "Start Free Trial"},
            "family": {"name": "Family", "price": "$9.99", "features": ["Everything in Personal", "Up to 6 devices", "Family Hub with E2E alerts", "Parental mode"], "cta": "Start Free Trial"},
        },
        "comparison": {
            "heading": "How we compare",
            "headers": ["Feature", "LinkShield", "Guardio", "NordVPN TP", "Norton 360", "Free Extensions"],
            "rows": [
                ["Price", "$4.99/mo", "$9.99/mo", "~$5/mo (w/ VPN)", "$40-100/yr", "Free"],
                ["Platforms", "All 5", "Chrome only", "Win/Mac", "All", "Browser only"],
                ["Privacy Audit", "✅", "❌", "❌", "❌", "❌"],
                ["On-device data", "✅", "❌", "❌", "❌", "❌"],
                ["ML detection", "✅", "✅", "✅", "✅", "❌"],
                ["Breach monitoring", "✅", "❌", "❌", "✅", "❌"],
                ["Family Hub", "✅ (E2E)", "❌", "❌", "✅", "❌"],
                ["B2B Phishing sim", "✅", "❌", "❌", "❌", "❌"],
            ],
        },
        "privacy": {
            "heading": "Privacy is not a feature. It's the architecture.",
            "server_heading": "What our server knows",
            "server_items": ["Your email address", "Subscription status", "Weekly aggregate numbers"],
            "server_note": "If breached: attacker gets emails + subscription. Boring.",
            "device_heading": "What stays on your device",
            "device_items": ["Full URL check history", "Privacy Audit results", "Security Score breakdown", "Weekly Report details", "Family alert content (E2E encrypted)"],
            "device_note": "If device is lost: protected by OS encryption.",
        },
        "testimonials": {
            "heading": "What users say",
            "items": [
                {"q": "Finally, a security tool that doesn't spy on me. The Privacy Audit is eye-opening.", "n": "Alex K.", "r": "Software Engineer"},
                {"q": "Caught 3 phishing links in my Gmail that Chrome missed. Worth every penny.", "n": "Maria S.", "r": "Marketing Manager"},
                {"q": "We replaced KnowBe4 with LinkShield Business. Same protection, 1/4 the price.", "n": "James T.", "r": "IT Director"},
            ],
        },
        "faq": {
            "heading": "FAQ",
            "items": [
                {"q": "How is my data protected?", "a": "Your browsing history never leaves your device. Our servers store only your email and subscription status. Even if we're breached, attackers learn nothing about your online activity."},
                {"q": "Does it slow down browsing?", "a": "No. 95% of checks happen locally via bloom filter in under 1ms. Only unknown domains are sent to our API (domain name only, never full URLs)."},
                {"q": "Can I use it with a VPN?", "a": "Yes! On mobile, LinkShield auto-detects your VPN and switches to DNS mode, working alongside NordVPN, ExpressVPN, or any other provider."},
                {"q": "What's different from Google Safe Browsing?", "a": "Google Safe Browsing is reactive — it catches known threats but misses new phishing. LinkShield adds ML detection, 8 additional threat sources, Privacy Audit, and doesn't send your browsing data to Google."},
                {"q": "Is there a free plan?", "a": "Yes! The free plan includes 10 API checks/day, unlimited local bloom filter checks, and basic Privacy Audit. Most casual users never need to upgrade."},
                {"q": "How does phishing simulation work?", "a": "Business plan includes simulated phishing emails sent to your team. Pick a template, we send test emails, track who clicks vs. who reports. For training, not punishment."},
            ],
        },
    },
    "ru": {
        "features": {
            "heading": "Всё, что нужно. Ничего лишнего.",
            "items": [
                {"icon": "🔍", "title": "Автоматическая проверка ссылок", "desc": "Каждая ссылка на каждой странице проверяется в 9 базах угроз. Красный, жёлтый и зелёный значки сразу показывают, можно ли кликать."},
                {"icon": "🔒", "title": "Аудит приватности", "desc": "Правый клик на любой странице показывает трекеры, куки, сбор данных и фингерпринтинг. Оценка от A до F."},
                {"icon": "🧠", "title": "Детекция на основе ML", "desc": "Модель CatBoost обучена на 18 тыс.+ доменов. AUC 0,9988. Ловит новый фишинг, который пропускают правила."},
                {"icon": "⚡", "title": "Мгновенная защита", "desc": "95% проверок выполняется локально через bloom-фильтр быстрее, чем за 1 мс. Без задержек."},
                {"icon": "📱", "title": "Ваши данные — на вашем устройстве", "desc": "История просмотров не попадает на наши серверы. Мы видим только имена доменов. Даже если нас взломают, ваши данные в безопасности."},
                {"icon": "📧", "title": "Сканер почты", "desc": "Находит фишинговые ссылки в Gmail и Outlook, которые пропустил браузер."},
            ],
        },
        "how_it_works": {"heading": "Как LinkShield вас защищает", "steps": [
            {"step": "1", "title": "Установите", "desc": "Добавьте расширение в Chrome. Займёт 10 секунд."},
            {"step": "2", "title": "Пользуйтесь", "desc": "LinkShield проверяет каждую ссылку автоматически. Ничего делать не нужно."},
            {"step": "3", "title": "Оставайтесь в безопасности", "desc": "Опасные ссылки помечаются красным. Нажмите, чтобы узнать подробности."},
        ]},
        "pricing_teaser": {"heading": "Простые и прозрачные цены", "unit_forever": "/навсегда", "unit_month": "/месяц", "most_popular": "Популярный выбор", "trial_note": "Все планы включают 14-дневный бесплатный период. Отмена в любой момент.",
            "free": {"name": "Free", "price": "$0", "features": ["10 API-проверок в день", "Неограниченные локальные проверки", "Аудит приватности (только оценка)", "Значки безопасности на всех страницах"], "cta": "Начать"},
            "personal": {"name": "Personal", "price": "$4.99", "features": ["Неограниченные проверки", "Полный разбор аудита приватности", "Еженедельный отчёт о безопасности", "Оценка безопасности + советы", "Приоритетная поддержка"], "cta": "Попробовать бесплатно"},
            "family": {"name": "Family", "price": "$9.99", "features": ["Всё из Personal", "До 6 устройств", "Семейный центр с E2E-оповещениями", "Родительский режим"], "cta": "Попробовать бесплатно"},
        },
        "comparison": {"heading": "Сравнение с альтернативами", "headers": ["Функция", "LinkShield", "Guardio", "NordVPN TP", "Norton 360", "Бесплатные расширения"], "rows": [
            ["Цена", "$4.99/мес", "$9.99/мес", "~$5/мес (с VPN)", "$40-100/год", "Бесплатно"],
            ["Платформы", "Все 5", "Только Chrome", "Win/Mac", "Все", "Только браузер"],
            ["Аудит приватности", "✅", "❌", "❌", "❌", "❌"],
            ["Данные на устройстве", "✅", "❌", "❌", "❌", "❌"],
            ["ML-детекция", "✅", "✅", "✅", "✅", "❌"],
            ["Мониторинг утечек", "✅", "❌", "❌", "✅", "❌"],
            ["Семейный центр", "✅ (E2E)", "❌", "❌", "✅", "❌"],
            ["B2B-симуляции фишинга", "✅", "❌", "❌", "❌", "❌"],
        ]},
        "privacy": {"heading": "Приватность — это не функция. Это архитектура.", "server_heading": "Что знает наш сервер", "server_items": ["Ваш email", "Статус подписки", "Еженедельные агрегированные числа"], "server_note": "Если нас взломают: злоумышленник получит email и статус подписки. Скучно.", "device_heading": "Что остаётся на вашем устройстве", "device_items": ["Полная история проверок URL", "Результаты аудита приватности", "Разбор оценки безопасности", "Подробности еженедельного отчёта", "Содержимое семейных оповещений (E2E-шифрование)"], "device_note": "Если устройство потеряно: защищено шифрованием ОС."},
        "testimonials": {"heading": "Что говорят пользователи", "items": [
            {"q": "Наконец-то инструмент безопасности, который не шпионит за мной. Аудит приватности открывает глаза.", "n": "Алексей К.", "r": "Инженер-программист"},
            {"q": "Поймал 3 фишинговые ссылки в моём Gmail, которые пропустил Chrome. Стоит своих денег.", "n": "Мария С.", "r": "Маркетолог"},
            {"q": "Мы заменили KnowBe4 на LinkShield Business. Такая же защита, в 4 раза дешевле.", "n": "Джеймс Т.", "r": "IT-директор"},
        ]},
        "faq": {"heading": "Частые вопросы", "items": [
            {"q": "Как защищены мои данные?", "a": "История просмотров никогда не покидает ваше устройство. На наших серверах хранится только email и статус подписки. Даже если нас взломают, злоумышленники ничего не узнают о вашей активности в интернете."},
            {"q": "Замедляет ли работу браузера?", "a": "Нет. 95% проверок выполняется локально через bloom-фильтр быстрее, чем за 1 мс. На наш API отправляются только неизвестные домены (только имя домена, никогда не полный URL)."},
            {"q": "Можно ли использовать с VPN?", "a": "Да! На мобильных устройствах LinkShield автоматически определяет VPN и переключается в режим DNS, работая вместе с NordVPN, ExpressVPN или любым другим провайдером."},
            {"q": "Чем отличается от Google Safe Browsing?", "a": "Google Safe Browsing — реактивный: ловит известные угрозы, но пропускает новый фишинг. LinkShield добавляет ML-детекцию, 8 дополнительных источников угроз, аудит приватности — и не отправляет данные о просмотрах в Google."},
            {"q": "Есть ли бесплатный план?", "a": "Да! Бесплатный план включает 10 API-проверок в день, неограниченные локальные проверки через bloom-фильтр и базовый аудит приватности. Большинству обычных пользователей хватит его навсегда."},
            {"q": "Как работает симуляция фишинга?", "a": "План Business включает симулированные фишинговые письма для вашей команды. Выберите шаблон — мы отправим тестовые письма и отследим, кто нажал ссылку, а кто сообщил об угрозе. Для обучения, а не наказания."},
        ]},
    },
    "es": {
        "features": {"heading": "Todo lo que necesitas. Nada de lo que no.", "items": [
            {"icon": "🔍", "title": "Escaneo automático de enlaces", "desc": "Cada enlace en cada página se verifica con 9 bases de amenazas. Insignias rojas, amarillas y verdes muestran la seguridad de un vistazo."},
            {"icon": "🔒", "title": "Auditoría de privacidad", "desc": "Clic derecho en cualquier página para ver rastreadores, cookies, recolección de datos y fingerprinting. Calificación de A a F."},
            {"icon": "🧠", "title": "Detección con IA", "desc": "Modelo CatBoost entrenado con más de 18.000 dominios. AUC 0,9988. Detecta phishing nuevo que los sistemas basados en reglas pasan por alto."},
            {"icon": "⚡", "title": "Protección instantánea", "desc": "El 95% de las verificaciones se hacen localmente con un bloom filter en menos de 1 ms. Sin demoras. Sin esperas."},
            {"icon": "📱", "title": "Tus datos, tu dispositivo", "desc": "El historial de navegación nunca llega a nuestros servidores. Solo vemos nombres de dominio. Aunque nos hackeen, tus datos están a salvo."},
            {"icon": "📧", "title": "Escáner de correo", "desc": "Encuentra enlaces de phishing en Gmail y Outlook que tu navegador dejó pasar."},
        ]},
        "how_it_works": {"heading": "Cómo te protege LinkShield", "steps": [
            {"step": "1", "title": "Instala", "desc": "Añade la extensión a Chrome. Toma 10 segundos."},
            {"step": "2", "title": "Navega", "desc": "LinkShield verifica cada enlace automáticamente. No hace falta hacer nada."},
            {"step": "3", "title": "Mantente seguro", "desc": "Los enlaces peligrosos reciben una insignia roja. Haz clic para ver detalles."},
        ]},
        "pricing_teaser": {"heading": "Precios simples y transparentes", "unit_forever": "/para siempre", "unit_month": "/mes", "most_popular": "Más popular", "trial_note": "Todos los planes incluyen 14 días de prueba gratis. Cancela cuando quieras.",
            "free": {"name": "Free", "price": "$0", "features": ["10 verificaciones API al día", "Verificaciones locales ilimitadas", "Auditoría de privacidad (solo calificación)", "Insignias de enlace en todas las páginas"], "cta": "Empezar"},
            "personal": {"name": "Personal", "price": "$4.99", "features": ["Verificaciones ilimitadas", "Auditoría de privacidad completa", "Informe semanal de seguridad", "Puntuación de seguridad + consejos", "Soporte prioritario"], "cta": "Empezar prueba gratis"},
            "family": {"name": "Family", "price": "$9.99", "features": ["Todo de Personal", "Hasta 6 dispositivos", "Centro Familiar con alertas E2E", "Modo parental"], "cta": "Empezar prueba gratis"}},
        "comparison": {"heading": "Cómo nos comparamos", "headers": ["Característica", "LinkShield", "Guardio", "NordVPN TP", "Norton 360", "Extensiones gratis"], "rows": [
            ["Precio", "$4.99/mes", "$9.99/mes", "~$5/mes (con VPN)", "$40-100/año", "Gratis"],
            ["Plataformas", "Las 5", "Solo Chrome", "Win/Mac", "Todas", "Solo navegador"],
            ["Auditoría de privacidad", "✅", "❌", "❌", "❌", "❌"],
            ["Datos en el dispositivo", "✅", "❌", "❌", "❌", "❌"],
            ["Detección por ML", "✅", "✅", "✅", "✅", "❌"],
            ["Monitoreo de filtraciones", "✅", "❌", "❌", "✅", "❌"],
            ["Centro Familiar", "✅ (E2E)", "❌", "❌", "✅", "❌"],
            ["Simulación de phishing B2B", "✅", "❌", "❌", "❌", "❌"],
        ]},
        "privacy": {"heading": "La privacidad no es una función. Es la arquitectura.", "server_heading": "Lo que sabe nuestro servidor", "server_items": ["Tu correo electrónico", "Estado de la suscripción", "Números agregados semanales"], "server_note": "Si nos hackean: el atacante obtiene correos + suscripciones. Aburrido.", "device_heading": "Lo que queda en tu dispositivo", "device_items": ["Historial completo de URL verificadas", "Resultados de la Auditoría de privacidad", "Desglose de la Puntuación de seguridad", "Detalles del Informe semanal", "Contenido de alertas familiares (cifrado E2E)"], "device_note": "Si pierdes el dispositivo: protegido por el cifrado del sistema operativo."},
        "testimonials": {"heading": "Lo que dicen los usuarios", "items": [
            {"q": "Por fin una herramienta de seguridad que no me espía. La Auditoría de privacidad abre los ojos.", "n": "Alex K.", "r": "Ingeniero de software"},
            {"q": "Atrapó 3 enlaces de phishing en mi Gmail que Chrome pasó por alto. Vale cada centavo.", "n": "María S.", "r": "Gerente de marketing"},
            {"q": "Reemplazamos KnowBe4 por LinkShield Business. La misma protección, a la cuarta parte del precio.", "n": "James T.", "r": "Director de TI"},
        ]},
        "faq": {"heading": "Preguntas frecuentes", "items": [
            {"q": "¿Cómo se protegen mis datos?", "a": "Tu historial de navegación nunca sale del dispositivo. Nuestros servidores solo almacenan tu correo y el estado de la suscripción. Aunque nos hackeen, los atacantes no aprenden nada sobre tu actividad en línea."},
            {"q": "¿Ralentiza la navegación?", "a": "No. El 95% de las verificaciones se hacen localmente con bloom filter en menos de 1 ms. Solo los dominios desconocidos se envían a nuestra API (solo el nombre del dominio, nunca la URL completa)."},
            {"q": "¿Puedo usarlo con una VPN?", "a": "¡Sí! En móvil, LinkShield detecta automáticamente tu VPN y cambia al modo DNS, funcionando junto a NordVPN, ExpressVPN o cualquier otro proveedor."},
            {"q": "¿Qué lo diferencia de Google Safe Browsing?", "a": "Google Safe Browsing es reactivo: atrapa amenazas conocidas pero deja pasar phishing nuevo. LinkShield añade detección por ML, 8 fuentes adicionales de amenazas, Auditoría de privacidad, y no envía tus datos de navegación a Google."},
            {"q": "¿Hay un plan gratuito?", "a": "¡Sí! El plan gratuito incluye 10 verificaciones API al día, verificaciones locales ilimitadas por bloom filter y Auditoría de privacidad básica. La mayoría de usuarios casuales nunca necesita actualizar."},
            {"q": "¿Cómo funciona la simulación de phishing?", "a": "El plan Business incluye correos de phishing simulados enviados a tu equipo. Elige una plantilla, enviamos correos de prueba y rastreamos quién hace clic y quién reporta. Para capacitar, no para castigar."},
        ]},
    },
    # For pt/fr/de/it/id/hi/ar: fall back to English for new sections — their
    # existing Nav/Hero/FinalCta/Footer stay translated. These 7 locales are
    # already marked "draft" in STATE.md and need native review anyway; falling
    # back to English for new sections keeps the site bilingual-viable and
    # signals clearly that translation is pending.
}


def merge_landing(target: dict[str, Any], sections: dict[str, Any]) -> None:
    """Overwrite the listed section keys under landing.* only."""
    landing = target.setdefault("landing", {})
    for key, value in sections.items():
        landing[key] = value


def main() -> int:
    en_sections = SECTIONS["en"]
    for locale_file in SOURCE_DIR.glob("*.json"):
        locale = locale_file.stem
        data = json.loads(locale_file.read_text(encoding="utf-8"))

        sections = SECTIONS.get(locale) or en_sections  # English fallback
        merge_landing(data, sections)

        locale_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"✓ Injected landing sections into {locale_file.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
