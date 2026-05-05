// Smoke test for packages/extension-core/src/utils/family-invite-url.js.
//
// The parser is the entry point grandma's extension hits when she pastes the
// link mom shared. Getting it wrong means a usability regression (manual
// re-entry of code+PIN); getting it tolerant of weird inputs is what stops
// "doesn't work, the link looks fine to me" support tickets.
//
// Run from repo root:
//   node scripts/_smoke_invite_url_parsing.cjs
//
// We intentionally do NOT use a test framework — the rest of the
// extension-side smoke tests (_smoke_family_crypto*.cjs) follow the same
// pattern, and we want zero npm dependencies for this layer.

const assert = require("assert/strict");

const { parseInviteUrl, buildInviteUrl } = require(
  "../packages/extension-core/src/utils/family-invite-url.js",
);

// ───────────────────────── buildInviteUrl ─────────────────────────

assert.equal(
  buildInviteUrl("ABC123", "9876"),
  "https://cleanway.ai/family/join#code=ABC123&pin=9876",
  "happy-path build should match the documented wire format",
);

assert.equal(
  buildInviteUrl("a/b+c", "0001"),
  "https://cleanway.ai/family/join#code=a%2Fb%2Bc&pin=0001",
  "code chars that need URL-encoding must be encoded",
);

// ───────────────────────── parseInviteUrl ─────────────────────────

// Round-trip: build then parse should recover the inputs exactly.
const built = buildInviteUrl("INVITE_42", "1357");
const parsed = parseInviteUrl(built);
assert.deepEqual(
  parsed,
  { code: "INVITE_42", pin: "1357" },
  "round-trip parse must equal the original inputs",
);

// URLs that look right.
assert.deepEqual(
  parseInviteUrl("https://cleanway.ai/family/join#code=ABC&pin=1234"),
  { code: "ABC", pin: "1234" },
  "canonical https URL parses cleanly",
);

assert.deepEqual(
  parseInviteUrl(" https://cleanway.ai/family/join#code=ABC&pin=1234 "),
  { code: "ABC", pin: "1234" },
  "leading/trailing whitespace tolerated (paste from clipboard)",
);

assert.deepEqual(
  parseInviteUrl("https://staging.cleanway.ai/family/join#code=ABC&pin=1234"),
  { code: "ABC", pin: "1234" },
  "subdomain *.cleanway.* still recognized",
);

// Trailing slash on the path is fine — \b anchor doesn't require end-of-string.
assert.deepEqual(
  parseInviteUrl("https://cleanway.ai/family/join/#code=ABC&pin=1234"),
  { code: "ABC", pin: "1234" },
  "trailing slash on path tolerated",
);

// URL-encoded chars in code survive.
const encoded = parseInviteUrl(
  "https://cleanway.ai/family/join#code=" + encodeURIComponent("a/b+c") + "&pin=0001",
);
assert.deepEqual(
  encoded,
  { code: "a/b+c", pin: "0001" },
  "URL-encoded code chars are decoded by the parser",
);

// ───────────────────────── parseInviteUrl: rejects ────────────────

assert.equal(parseInviteUrl(""), null, "empty input → null");
assert.equal(parseInviteUrl(null), null, "null → null");
assert.equal(parseInviteUrl(undefined), null, "undefined → null");

assert.equal(
  parseInviteUrl("not a url at all"),
  null,
  "garbage input → null (URL constructor throws)",
);

assert.equal(
  parseInviteUrl("https://example.com/family/join#code=ABC&pin=1234"),
  null,
  "wrong hostname → null (only cleanway.* allowed)",
);

assert.equal(
  parseInviteUrl("https://evilcleanway.attacker.com/family/join#code=ABC&pin=1234"),
  null,
  "phishing-style hostname (attacker controlled) → null",
);

assert.equal(
  parseInviteUrl("https://cleanway.ai/login#code=ABC&pin=1234"),
  null,
  "wrong path → null",
);

assert.equal(
  parseInviteUrl("https://cleanway.ai/family/join"),
  null,
  "URL with no hash params → null",
);

assert.equal(
  parseInviteUrl("https://cleanway.ai/family/join#code=ABC"),
  null,
  "missing pin → null",
);

assert.equal(
  parseInviteUrl("https://cleanway.ai/family/join#pin=1234"),
  null,
  "missing code → null",
);

// Plain code/PIN without URL — caller should keep using manual input path.
assert.equal(parseInviteUrl("ABC123"), null, "bare code is not a URL");

console.log("✓ family-invite-url smoke test passed (16 assertions)");
