/**
 * The only "internet" the smoke test's Firefox has: a local proxy that
 * answers every request itself.
 *
 * Firefox is pointed at it for http and https (proxyPrefs below), so nothing
 * it asks for — the extension's background, popup, content scripts, the
 * browser's own services — reaches a real server, and it resolves no names
 * itself. For https the proxy accepts the CONNECT and speaks TLS itself with
 * a throwaway self-signed certificate (openssl, made per run in a temp dir);
 * the WebDriver session has acceptInsecureCerts, so Firefox takes it. Then:
 *   - api.cleanway.ai: the store-screenshot stub (store-screenshots/network.mjs):
 *     a site check gets the verdict the extension's OWN offline rules give
 *     that host, /health 200, anything else 404. No verdict is invented.
 *   - the demo hosts of store-screenshots/fixtures.mjs: their pages.
 *   - anything else: the connection is dropped, as if the name did not
 *     resolve, and the address is logged.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { join } from "node:path";
import { pageFor } from "../store-screenshots/fixtures.mjs";
import { API_HOST, stubAnswer } from "../store-screenshots/network.mjs";

/** A self-signed certificate for the stub, written into `dir`. */
function makeCert(dir) {
  const key = join(dir, "stub-key.pem");
  const cert = join(dir, "stub-cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
    "-subj", "/CN=cleanway-firefox-smoke-stub", "-keyout", key, "-out", cert], { stdio: "ignore" });
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

/**
 * Start the proxy on 127.0.0.1 (a free port).
 * @param {{dir: string, lang: string, score: (host: string) => object}} opts
 * @returns {Promise<{port: number, log: {api: string[], pages: string[], refused: Set<string>}, close: () => void}>}
 */
export async function startStubProxy({ dir, lang, score }) {
  const log = { api: [], pages: [], refused: new Set() };

  function answer(req, res, scheme) {
    const host = (req.headers.host || "").replace(/:\d+$/, "");
    let u;
    try {
      // Through the proxy a plain-http request carries its whole address;
      // inside the TLS tunnel only the path.
      u = new URL(req.url, `${scheme}://${host || "unknown.invalid"}`);
    } catch (e) {
      req.socket.destroy();
      return;
    }
    const path = `${u.pathname}${u.search}`;
    const url = `${scheme}://${host}${path}`;
    if (host === API_HOST) {
      const [status, body] = stubAnswer(req.method, url, score);
      log.api.push(`${req.method} ${path} → ${status}${body.level ? ` ${body.level}` : ""}`);
      // Like the real API: no CORS headers for a web page's own origin.
      const origin = req.headers.origin || "";
      const cors = /^https?:/.test(origin) ? {} : { "Access-Control-Allow-Origin": "*" };
      res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors });
      res.end(JSON.stringify(body));
      return;
    }
    const html = pageFor(url, lang);
    if (html) {
      log.pages.push(`${req.method} ${url}`);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(html);
      return;
    }
    // A demo site without an icon, rather than a dropped connection.
    if (u.pathname === "/favicon.ico" && pageFor(`${scheme}://${host}/`, lang)) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("no icon");
      return;
    }
    log.refused.add(`${scheme}://${host}${u.pathname}`);
    req.socket.destroy();
  }

  const tls = createHttpsServer(makeCert(dir), (req, res) => answer(req, res, "https"));
  const proxy = createHttpServer((req, res) => answer(req, res, "http"));
  for (const server of [tls, proxy]) {
    // WebSockets (the browser's push service): nobody answers.
    server.on("upgrade", (req, socket) => {
      log.refused.add(`ws://${req.headers.host || "?"}${req.url}`);
      socket.destroy();
    });
    server.on("clientError", (err, socket) => socket.destroy());
  }
  proxy.on("connect", (req, socket, head) => {
    socket.on("error", () => {});
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length) socket.unshift(head);
    tls.emit("connection", socket);
  });
  await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  return {
    port: proxy.address().port,
    log,
    close: () => {
      proxy.closeAllConnections?.();
      tls.closeAllConnections?.();
      proxy.close();
      tls.close();
    },
  };
}

/** Firefox prefs that send every http(s) request to the proxy and nowhere else. */
export function proxyPrefs(port) {
  return {
    "network.proxy.type": 1,
    "network.proxy.http": "127.0.0.1",
    "network.proxy.http_port": port,
    "network.proxy.ssl": "127.0.0.1",
    "network.proxy.ssl_port": port,
    "network.proxy.share_proxy_settings": false,
    "network.proxy.no_proxies_on": "",
    "network.proxy.failover_direct": false,
    // No DNS of its own: no DNS-over-HTTPS, no prefetching.
    "network.trr.mode": 5,
    "network.dns.disablePrefetch": true,
    "network.prefetch-next": false,
    "network.http.speculative-parallel-limit": 0,
  };
}
