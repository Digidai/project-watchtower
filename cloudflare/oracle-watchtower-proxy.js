const ORIGIN = "http://oracle-origin.syncany.app";

function originUrl(requestUrl) {
  const incoming = new URL(requestUrl);
  const target = new URL(ORIGIN);
  target.pathname = incoming.pathname;
  target.search = incoming.search;
  return target;
}

export default {
  async fetch(request) {
    const target = originUrl(request.url);
    const headers = new Headers(request.headers);

    headers.delete("Host");
    headers.set("X-Forwarded-Host", new URL(request.url).host);
    headers.set("X-Forwarded-Proto", "https");

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
    };

    if (!["GET", "HEAD"].includes(request.method)) {
      init.body = request.body;
    }

    const response = await fetch(target, init);
    const proxied = new Response(response.body, response);
    proxied.headers.set("X-Watchtower-Proxy", "cloudflare-worker");
    proxied.headers.set("Cache-Control", "no-store, max-age=0");
    return proxied;
  },
};
