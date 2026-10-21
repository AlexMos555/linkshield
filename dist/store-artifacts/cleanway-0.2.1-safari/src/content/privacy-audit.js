/**
 * Privacy Audit — 100% On-Device DOM Analysis
 *
 * Scans the current page for privacy-relevant elements:
 *   - Third-party trackers (scripts, pixels, iframes)
 *   - Cookies (first-party, third-party)
 *   - Data collection forms (email, password, credit card, phone)
 *   - Browser permissions requested (camera, mic, location, notifications)
 *   - Fingerprinting scripts (canvas, WebGL, audio)
 *
 * Results NEVER leave the device. Grade A-F computed locally.
 * Free tier: grade only. Paid tier: full breakdown.
 */

// Known tracker domains (subset — full list bundled separately)
const TRACKER_DOMAINS = new Set([
  // Analytics
  "google-analytics.com", "googletagmanager.com", "analytics.google.com",
  "hotjar.com", "mixpanel.com", "segment.com", "amplitude.com",
  "heap.io", "fullstory.com", "mouseflow.com", "luckyorange.com",
  "clarity.ms", "plausible.io", "matomo.org",
  // Advertising
  "doubleclick.net", "googlesyndication.com", "googleadservices.com",
  "facebook.net", "connect.facebook.net", "fbcdn.net",
  "ads-twitter.com", "ads.linkedin.com", "adsrvr.org",
  "criteo.com", "outbrain.com", "taboola.com",
  "amazon-adsystem.com", "bing.com/bat.js",
  // Social
  "platform.twitter.com", "platform.linkedin.com",
  "connect.facebook.net", "apis.google.com",
  // Fingerprinting / Fraud detection
  "fingerprintjs.com", "fpjs.io", "datadome.co",
  "perimeterx.net", "kasada.io",
]);

// Sensitive form field patterns
const SENSITIVE_PATTERNS = {
  email: /email|e-mail|correo/i,
  password: /password|passwd|pass/i,
  phone: /phone|tel|mobile|celular/i,
  credit_card: /card|credit|cc-num|cardnumber/i,
  ssn: /ssn|social.?security|national.?id/i,
  address: /address|street|city|zip|postal/i,
  name: /^name$|full.?name|first.?name|last.?name/i,
};

// Fingerprinting API signatures
const FINGERPRINT_APIS = [
  "HTMLCanvasElement.prototype.toDataURL",
  "HTMLCanvasElement.prototype.toBlob",
  "CanvasRenderingContext2D.prototype.getImageData",
  "WebGLRenderingContext.prototype.getParameter",
  "AudioContext",
  "OfflineAudioContext",
  "navigator.getBattery",
  "navigator.deviceMemory",
  "navigator.hardwareConcurrency",
  "navigator.connection",
  "screen.colorDepth",
];


/**
 * Run complete privacy audit on current page
 * @returns {AuditResult}
 */
export function runPrivacyAudit() {
  const trackers = detectTrackers();
  const cookies = countCookies();
  const forms = detectSensitiveForms();
  const permissions = detectPermissions();
  const fingerprinting = detectFingerprinting();

  // Calculate grade
  const grade = calculateGrade({
    trackerCount: trackers.length,
    thirdPartyCookies: cookies.thirdParty,
    sensitiveFields: forms.length,
    permissionsRequested: permissions.length,
    fingerprintingDetected: fingerprinting.detected,
  });

  return {
    grade: grade.letter,
    gradeScore: grade.score,
    domain: window.location.hostname,
    scannedAt: new Date().toISOString(),
    summary: {
      trackers: trackers.length,
      cookies: { firstParty: cookies.firstParty, thirdParty: cookies.thirdParty },
      sensitiveFields: forms.length,
      permissions: permissions.length,
      fingerprinting: fingerprinting.detected,
    },
    // Detailed breakdown (for paid users)
    details: {
      trackers,
      forms,
      permissions,
      fingerprinting: fingerprinting.methods,
      cookies,
    },
  };
}


/**
 * Detect third-party trackers (scripts, iframes, pixels)
 */
function detectTrackers() {
  const found = [];
  const pageHost = window.location.hostname;

  // Check all scripts
  const scripts = document.querySelectorAll("script[src]");
  for (const script of scripts) {
    try {
      const url = new URL(script.src);
      if (url.hostname !== pageHost && isTracker(url.hostname)) {
        found.push({
          type: "script",
          domain: url.hostname,
          category: categorizeTracker(url.hostname),
        });
      }
    } catch {}
  }

  // Check iframes
  const iframes = document.querySelectorAll("iframe[src]");
  for (const iframe of iframes) {
    try {
      const url = new URL(iframe.src);
      if (url.hostname !== pageHost && isTracker(url.hostname)) {
        found.push({
          type: "iframe",
          domain: url.hostname,
          category: categorizeTracker(url.hostname),
        });
      }
    } catch {}
  }

  // Check tracking pixels (1x1 images)
  const images = document.querySelectorAll("img");
  for (const img of images) {
    if (img.width <= 2 && img.height <= 2 && img.src) {
      try {
        const url = new URL(img.src);
        if (url.hostname !== pageHost) {
          found.push({
            type: "pixel",
            domain: url.hostname,
            category: "tracking",
          });
        }
      } catch {}
    }
  }

  // Deduplicate by domain
  const seen = new Set();
  return found.filter((t) => {
    if (seen.has(t.domain)) return false;
    seen.add(t.domain);
    return true;
  });
}

function isTracker(hostname) {
  for (const tracker of TRACKER_DOMAINS) {
    if (hostname === tracker || hostname.endsWith("." + tracker)) {
      return true;
    }
  }
  return false;
}

function categorizeTracker(hostname) {
  if (hostname.includes("analytics") || hostname.includes("hotjar") || hostname.includes("mixpanel") || hostname.includes("clarity") || hostname.includes("heap") || hostname.includes("amplitude") || hostname.includes("segment") || hostname.includes("fullstory"))
    return "analytics";
  if (hostname.includes("doubleclick") || hostname.includes("adsyndication") || hostname.includes("adservice") || hostname.includes("criteo") || hostname.includes("outbrain") || hostname.includes("taboola"))
    return "advertising";
  if (hostname.includes("facebook") || hostname.includes("twitter") || hostname.includes("linkedin"))
    return "social";
  if (hostname.includes("fingerprint") || hostname.includes("datadome") || hostname.includes("perimeterx"))
    return "fingerprinting";
  return "tracking";
}

/**
 * Count cookies
 */
function countCookies() {
  const allCookies = document.cookie.split(";").filter((c) => c.trim());
  return {
    total: allCookies.length,
    firstParty: allCookies.length, // Same-site cookies
    thirdParty: 0, // Can't access cross-origin cookies from content script
    // Note: accurate 3rd-party count requires background script + cookies API
  };
}

/**
 * Detect forms collecting sensitive data
 */
function detectSensitiveForms() {
  const results = [];
  const inputs = document.querySelectorAll("input, select, textarea");

  for (const input of inputs) {
    const name = input.name || "";
    const id = input.id || "";
    const type = input.type || "";
    const placeholder = input.placeholder || "";
    const label = getInputLabel(input);
    const combined = `${name} ${id} ${type} ${placeholder} ${label}`.toLowerCase();

    for (const [fieldType, pattern] of Object.entries(SENSITIVE_PATTERNS)) {
      if (pattern.test(combined)) {
        results.push({
          fieldType,
          inputType: type,
          hasAutocomplete: !!input.autocomplete,
        });
        break; // One match per input
      }
    }
  }

  return results;
}

function getInputLabel(input) {
  // Try label[for]
  if (input.id) {
    const label = document.querySelector(`label[for="${input.id}"]`);
    if (label) return label.textContent;
  }
  // Try parent label
  const parent = input.closest("label");
  if (parent) return parent.textContent;
  return "";
}

/**
 * Detect browser permission requests
 */
function detectPermissions() {
  const requested = [];

  // Check for permission-related APIs in scripts
  const scriptContent = document.documentElement.innerHTML;

  const permChecks = [
    { api: "navigator.geolocation", perm: "location" },
    { api: "getUserMedia", perm: "camera/microphone" },
    { api: "Notification.requestPermission", perm: "notifications" },
    { api: "navigator.clipboard", perm: "clipboard" },
    { api: "navigator.bluetooth", perm: "bluetooth" },
    { api: "navigator.usb", perm: "usb" },
  ];

  for (const check of permChecks) {
    if (scriptContent.includes(check.api)) {
      requested.push(check.perm);
    }
  }

  return requested;
}

/**
 * Detect fingerprinting attempts
 */
function detectFingerprinting() {
  const methods = [];
  const scriptContent = document.documentElement.innerHTML;

  // Canvas fingerprinting
  if (scriptContent.includes("toDataURL") && scriptContent.includes("fillText")) {
    methods.push("canvas");
  }

  // WebGL fingerprinting
  if (scriptContent.includes("getParameter") && scriptContent.includes("WebGL")) {
    methods.push("webgl");
  }

  // Audio fingerprinting
  if (scriptContent.includes("AudioContext") || scriptContent.includes("OfflineAudioContext")) {
    methods.push("audio");
  }

  // Battery fingerprinting
  if (scriptContent.includes("getBattery")) {
    methods.push("battery");
  }

  // Hardware fingerprinting
  if (scriptContent.includes("hardwareConcurrency") || scriptContent.includes("deviceMemory")) {
    methods.push("hardware");
  }

  return {
    detected: methods.length > 0,
    methods,
  };
}

/**
 * Calculate privacy grade A-F
 */
function calculateGrade(metrics) {
  let score = 100;

  // Trackers: -3 each, max -40
  score -= Math.min(metrics.trackerCount * 3, 40);

  // Third-party cookies: -2 each, max -20
  score -= Math.min(metrics.thirdPartyCookies * 2, 20);

  // Sensitive fields: -5 each, max -25
  score -= Math.min(metrics.sensitiveFields * 5, 25);

  // Permissions: -8 each, max -25
  score -= Math.min(metrics.permissionsRequested * 8, 25);

  // Fingerprinting: -15
  if (metrics.fingerprintingDetected) score -= 15;

  score = Math.max(0, Math.min(100, score));

  let letter;
  if (score >= 90) letter = "A";
  else if (score >= 80) letter = "B";
  else if (score >= 65) letter = "C";
  else if (score >= 50) letter = "D";
  else letter = "F";

  return { score, letter };
}
