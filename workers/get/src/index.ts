/**
 * Preston-Check install redirect Worker
 *
 * Serves get.preston-check.com — proxies install.sh from the latest
 * GitHub Release so that `curl -fsSL https://get.preston-check.com/install.sh`
 * works with a valid TLS cert (Cloudflare-managed).
 *
 * All other paths redirect to the GitHub Release page.
 */

const RELEASE_BASE =
  "https://github.com/preston-check/preston-check/releases/latest/download";

export default {
  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/install.sh") {
      const upstream = await fetch(`${RELEASE_BASE}/install.sh`, {
        headers: { "User-Agent": "preston-check-get-worker" },
      });
      return new Response(upstream.body, {
        status: upstream.status,
        headers: {
          "Content-Type": "text/x-shellscript",
          "Cache-Control": "no-store",
          "X-Source": "github-release",
        },
      });
    }

    return Response.redirect(
      "https://github.com/preston-check/preston-check/releases/latest",
      302
    );
  },
} satisfies ExportedHandler;
