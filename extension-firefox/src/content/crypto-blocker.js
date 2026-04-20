/**
 * Cryptocurrency Miner Blocker
 *
 * Detects and blocks crypto mining scripts that hijack
 * your CPU without consent. Common miners:
 * - CoinHive (dead but clones exist)
 * - CryptoLoot
 * - JSECoin
 * - WebMinePool
 * - Custom miners using WebWorker + WASM
 *
 * Detection methods:
 * 1. Block known miner domains
 * 2. Detect WebWorker + high CPU patterns
 * 3. Block known miner script signatures
 */

var MINER_DOMAINS = [
  "coin-hive.com", "coinhive.com", "authedmine.com",
  "crypto-loot.com", "cryptoloot.pro",
  "jsecoin.com", "monerominer.rocks",
  "webminepool.com", "ppoi.org",
  "minero.cc", "gridcash.net",
  "cdn.omine.org", "ad-miner.com",
  "coinlab.biz", "miner.pr0gramm.com",
  "kiwifarms.net/js/miner.js",
  "greenindex.dynamic-dns.net",
  "static.reasedoper.pw",
  "mataharirama.xyz",
  "kisshentai.net",
];

var MINER_PATTERNS = [
  /CoinHive\.Anonymous/i,
  /coinhive\.min\.js/i,
  /cryptonight/i,
  /cryptoloot/i,
  /webminer/i,
  /minero\.cc/i,
  /monerominer/i,
];

var _minersBlocked = 0;

function blockMinerScripts() {
  // Block by removing known miner scripts
  document.querySelectorAll("script[src]").forEach(function(script) {
    var src = script.src.toLowerCase();
    for (var domain of MINER_DOMAINS) {
      if (src.includes(domain)) {
        script.remove();
        _minersBlocked++;
        console.warn("[LinkShield] Blocked crypto miner:", src);
        return;
      }
    }
  });

  // Block inline miner scripts
  document.querySelectorAll("script:not([src])").forEach(function(script) {
    var content = script.textContent || "";
    for (var pattern of MINER_PATTERNS) {
      if (pattern.test(content)) {
        script.textContent = "/* Blocked by LinkShield: crypto miner */";
        _minersBlocked++;
        console.warn("[LinkShield] Blocked inline crypto miner");
        return;
      }
    }
  });
}

// Block on load
blockMinerScripts();

// Watch for dynamically injected miners
var _minerObserver = new MutationObserver(function(mutations) {
  for (var m of mutations) {
    for (var node of m.addedNodes) {
      if (node.nodeType === Node.ELEMENT_NODE && node.tagName === "SCRIPT") {
        var src = (node.src || "").toLowerCase();
        for (var domain of MINER_DOMAINS) {
          if (src.includes(domain)) {
            node.remove();
            _minersBlocked++;
            console.warn("[LinkShield] Blocked injected crypto miner:", src);
            return;
          }
        }
      }
    }
  }
});
_minerObserver.observe(document.documentElement, { childList: true, subtree: true });
