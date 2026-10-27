// Minimal Node HTTP → Fetch API adapter for the SSR build's `{fetch}`
// handler (dist/server/server.js). TanStack Start's Vite plugin emits a
// Web-standard fetch handler rather than a Node listener in this version,
// so this bridges the two — the same shape any edge/worker runtime would
// call directly, adapted to node:http for a plain container deployment.
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const PORT = Number(process.env.PORT ?? 3000);
const HOST = process.env.HOST ?? "0.0.0.0";
const DIST_CLIENT = join(import.meta.dirname, "dist", "client");

const CONTENT_TYPES = {
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
};

const { default: handler } = await import("./dist/server/server.js");

function serveStatic(pathname) {
  const filePath = join(DIST_CLIENT, pathname);
  if (!filePath.startsWith(DIST_CLIENT)) return null; // path traversal guard
  if (!existsSync(filePath) || !statSync(filePath).isFile()) return null;
  return { body: readFileSync(filePath), type: CONTENT_TYPES[extname(filePath)] };
}

createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "GET" && url.pathname.startsWith("/assets/")) {
      const asset = serveStatic(url.pathname);
      if (asset) {
        res.writeHead(200, { "content-type": asset.type ?? "application/octet-stream" });
        res.end(asset.body);
        return;
      }
    }

    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      headers.set(key, Array.isArray(value) ? value.join(", ") : value);
    }

    const body =
      req.method === "GET" || req.method === "HEAD"
        ? undefined
        : await new Promise((resolve) => {
            const chunks = [];
            req.on("data", (c) => chunks.push(c));
            req.on("end", () => resolve(Buffer.concat(chunks)));
          });

    const request = new Request(url, { method: req.method, headers, body });
    const response = await handler.fetch(request, {}, {});

    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    if (response.body) {
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
    }
    res.end();
  } catch (error) {
    console.error(error);
    res.writeHead(500, { "content-type": "text/plain" });
    res.end("Internal Server Error");
  }
}).listen(PORT, HOST, () => {
  console.log(`insyte frontend listening on http://${HOST}:${PORT}`);
});
