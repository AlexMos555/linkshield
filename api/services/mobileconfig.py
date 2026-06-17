"""iOS .mobileconfig generator — Strategy doc Top-20 #6.

A Configuration Profile is an XML .plist Apple ships in
iOS/iPadOS/macOS that lets a user one-tap install system-wide
preferences. The DNSSettings payload is one of the supported
types and configures the device's resolver — including DoH /
DoT — for ALL apps, not just Safari.

For Cleanway this means: the user taps the cleanway.ai/dns
button on their iPhone, iOS shows the standard
"Install Profile?" dialog, and after one tap the entire phone
routes DNS through dns.cleanway.ai (our DoH gateway) — Safari,
Chrome, Mail, in-app browsers, everything.

This module assembles the profile XML. Signing it requires an
Apple Developer certificate and lives outside the codebase
(security/signed-mobileconfig README). The unsigned profile
still installs — iOS warns 'Unsigned' but the actual functional
behaviour is identical.
"""

from __future__ import annotations

import re
import uuid
from html import escape

PROFILE_DOMAIN = "ai.cleanway"
PROFILE_VERSION = 1

# Templates use double-curly-brace escaping intentionally so the
# .format() pass below ONLY substitutes our explicit placeholders.
# This is safer than rendering with a template engine because the
# input set is fixed.
_PROFILE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>{server_url}</string>
      </dict>
      <key>PayloadDescription</key>
      <string>{payload_description}</string>
      <key>PayloadDisplayName</key>
      <string>{payload_display_name}</string>
      <key>PayloadIdentifier</key>
      <string>{payload_identifier}</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>{payload_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>ProhibitDisablement</key>
      <false/>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>{profile_description}</string>
  <key>PayloadDisplayName</key>
  <string>{profile_display_name}</string>
  <key>PayloadIdentifier</key>
  <string>{profile_identifier}</string>
  <key>PayloadOrganization</key>
  <string>Cleanway</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadScope</key>
  <string>System</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""


_SERVER_URL_PATTERN = re.compile(
    r"^https://[A-Za-z0-9.\-]{1,253}(/[A-Za-z0-9._\-/?&=%]{0,128})?$"
)


def _is_valid_server_url(url: str) -> bool:
    """Strict whitelist on the DoH server URL.

    Per Apple's profile validator the ServerURL must be https://
    and resolve a /dns-query endpoint. We refuse anything else
    so a typo / injection attempt produces a profile that won't
    install rather than one that points users at a bad host.
    """
    return bool(url and _SERVER_URL_PATTERN.match(url))


def build_profile(
    server_url: str = "https://dns.cleanway.ai/dns-query",
    *,
    profile_uuid: str | None = None,
    payload_uuid: str | None = None,
    locale: str = "en",
) -> str:
    """Build the .mobileconfig XML string.

    `profile_uuid` and `payload_uuid` are exposed for tests and
    deterministic re-generation. In production we generate fresh
    UUIDs per download so cache busters / per-user revocation
    works at the device level.

    `locale` selects the user-facing strings only. Apple's
    installer surfaces these on the iPhone screen verbatim, so
    they should read naturally in the user's language.
    """
    if not _is_valid_server_url(server_url):
        raise ValueError(f"unsafe ServerURL: {server_url!r}")

    profile_uuid = profile_uuid or str(uuid.uuid4()).upper()
    payload_uuid = payload_uuid or str(uuid.uuid4()).upper()

    # Locale-specific user-facing strings. Apple shows these in the
    # profile install dialog, so they should read like a native
    # iOS settings string — "Cleanway Phishing-Blocking DNS"
    # rather than a marketing slogan.
    L = _PROFILE_STRINGS.get(locale.lower(), _PROFILE_STRINGS["en"])

    return _PROFILE_TEMPLATE.format(
        server_url=escape(server_url),
        payload_description=escape(L["payload_description"]),
        payload_display_name=escape(L["payload_display_name"]),
        payload_identifier=f"{PROFILE_DOMAIN}.dns.payload",
        payload_uuid=payload_uuid,
        profile_description=escape(L["profile_description"]),
        profile_display_name=escape(L["profile_display_name"]),
        profile_identifier=f"{PROFILE_DOMAIN}.dns",
        profile_uuid=profile_uuid,
    )


# Locale-specific user-facing strings shown during install.
# Keep these SHORT — Apple's install sheet truncates beyond
# ~60 chars on small phones.
_PROFILE_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "payload_description": "Routes DNS through Cleanway's phishing-blocking resolver.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "System-wide phishing protection via DNS. Removable any time in Settings → General → VPN & Device Management.",
        "profile_display_name": "Cleanway Phishing Shield",
    },
    "ru": {
        "payload_description": "Перенаправляет DNS-запросы через резолвер Cleanway, блокирующий фишинг.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Системная защита от фишинга через DNS. Удаляется в Настройки → Основные → VPN и управление устройством.",
        "profile_display_name": "Cleanway: защита от фишинга",
    },
    "es": {
        "payload_description": "Enruta DNS a través del resolver anti-phishing de Cleanway.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Protección anti-phishing en todo el sistema vía DNS. Eliminable en Ajustes → General → VPN y gestión de dispositivos.",
        "profile_display_name": "Cleanway: escudo anti-phishing",
    },
    "pt": {
        "payload_description": "Roteia DNS pelo resolvedor anti-phishing da Cleanway.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Proteção contra phishing em todo o sistema via DNS. Removível em Ajustes → Geral → VPN e Gerenciamento de Dispositivo.",
        "profile_display_name": "Cleanway: escudo contra phishing",
    },
    "hi": {
        "payload_description": "DNS को Cleanway के फ़िशिंग-ब्लॉकिंग रिज़ॉल्वर के माध्यम से रूट करता है।",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "DNS के ज़रिए सिस्टम-व्यापी फ़िशिंग सुरक्षा। Settings → General → VPN & Device Management में कभी भी हटाएँ।",
        "profile_display_name": "Cleanway फ़िशिंग सुरक्षा",
    },
    "de": {
        "payload_description": "Leitet DNS über Cleanways Phishing-blockierenden Resolver.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Systemweiter Phishing-Schutz via DNS. Jederzeit unter Einstellungen → Allgemein → VPN & Geräteverwaltung entfernbar.",
        "profile_display_name": "Cleanway: Phishing-Schutz",
    },
    "fr": {
        "payload_description": "Achemine DNS via le résolveur anti-phishing de Cleanway.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Protection anti-phishing à l'échelle du système via DNS. Supprimable à Réglages → Général → VPN et gestion des appareils.",
        "profile_display_name": "Cleanway : bouclier anti-phishing",
    },
    "it": {
        "payload_description": "Instrada DNS tramite il resolver anti-phishing di Cleanway.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Protezione anti-phishing a livello di sistema tramite DNS. Rimovibile in Impostazioni → Generali → VPN e Gestione Dispositivi.",
        "profile_display_name": "Cleanway: scudo anti-phishing",
    },
    "ar": {
        "payload_description": "يوجه DNS عبر محلل Cleanway المضاد للتصيد.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "حماية مضادة للتصيد على مستوى النظام عبر DNS. يمكن إزالتها في الإعدادات → عام → VPN وإدارة الأجهزة.",
        "profile_display_name": "Cleanway: درع مضاد للتصيد",
    },
    "id": {
        "payload_description": "Mengarahkan DNS melalui resolver anti-phishing Cleanway.",
        "payload_display_name": "Cleanway DNS",
        "profile_description": "Perlindungan anti-phishing seluruh sistem via DNS. Hapus di Pengaturan → Umum → VPN & Manajemen Perangkat kapan saja.",
        "profile_display_name": "Cleanway: perisai anti-phishing",
    },
}
