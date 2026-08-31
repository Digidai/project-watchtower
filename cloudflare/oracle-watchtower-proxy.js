const ORIGIN = "https://oracle-origin.syncany.app";

function unavailable() {
  return new Response("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Project Watchtower</title><main><h1>状态入口维护中</h1><p>此受限入口正在进行安全升级，暂不接受登录。请稍后再试。</p><p>仅供授权人员访问。请勿扫描、自动尝试密码或提交敏感信息。</p></main></html>", {
    status: 503,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Retry-After": "300", "Strict-Transport-Security": "max-age=31536000",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff" },
  });
}

function originUrl(requestUrl) {
  const incoming = new URL(requestUrl);
  const target = new URL(ORIGIN);
  target.pathname = incoming.pathname;
  target.search = incoming.search;
  return target;
}

export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);
    if (incoming.protocol !== "https:") {
      incoming.protocol = "https:";
      return Response.redirect(incoming.toString(), 308);
    }
    if (!env.WATCHTOWER_ORIGIN_SECRET) {
      return unavailable();
    }
    if (!["GET", "HEAD", "POST"].includes(request.method)) {
      return new Response("Method not allowed", { status: 405 });
    }
    if (request.method === "POST" && incoming.pathname !== "/login") {
      return new Response("Not found", { status: 404 });
    }
    const target = originUrl(request.url);
    const headers = new Headers(request.headers);

    headers.delete("Host");
    headers.set("X-Forwarded-Host", new URL(request.url).host);
    headers.set("X-Forwarded-Proto", "https");
    headers.set("X-Watchtower-Origin", env.WATCHTOWER_ORIGIN_SECRET);
    headers.set("X-Watchtower-Client-IP", request.headers.get("CF-Connecting-IP") || "unknown");

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(20000),
    };

    if (!["GET", "HEAD"].includes(request.method)) {
      // Bound memory and give the tunnel a fixed-length form, not chunked HTTP.
      const reader = request.body?.getReader();
      const chunks = [];
      let length = 0;
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          length += value.byteLength;
          if (length > 4096) {
            await reader.cancel();
            return new Response("Request too large", { status: 413 });
          }
          chunks.push(value);
        }
      }
      const body = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
      headers.delete("Transfer-Encoding");
      headers.set("Content-Length", String(length));
      init.body = body;
    }

    let response;
    try {
      response = await fetch(target, init);
    } catch {
      return unavailable();
    }
    if (response.headers.get("X-Watchtower-App") !== "dashboard-v2" || response.status >= 500 || response.status === 403) return unavailable();
    const proxied = new Response(response.body, response);
    proxied.headers.set("X-Watchtower-Proxy", "cloudflare-worker");
    proxied.headers.set("Cache-Control", "no-store, max-age=0");
    proxied.headers.set("Strict-Transport-Security", "max-age=31536000");
    return proxied;
  },
};
