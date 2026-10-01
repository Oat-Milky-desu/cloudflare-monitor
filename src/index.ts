import { addresses, HttpError, observedIP, readJson, withObservedIP } from "./config";
import { digest, equalHash, requireOrigin, sessionCookie, sessionToken } from "./security";
import { sendBark } from "./bark";
import { installationCommand, installationScript } from "./install";
export { ServerMonitor } from "./monitor";
export { ControlPlane } from "./control";

function json(value: unknown, status = 200, extra: HeadersInit = {}): Response {
  const headers = new Headers(extra);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return Response.json(value, { status, headers });
}
async function adminSession(request: Request, env: Env, mutation = false) {
  const token = sessionToken(request);
  const session = token ? await env.CONTROL.getByName("control").session(token) : null;
  if (!session || !token) throw new HttpError(401, "请先登录");
  if (mutation) {
    requireOrigin(request);
    if (!equalHash(request.headers.get("X-CSRF-Token") ?? "", session.csrfToken)) throw new HttpError(403, "会话校验失败，请刷新页面");
  }
  return { ...session, token };
}
function method(request: Request, expected: string): void { if (request.method !== expected) throw new HttpError(405, `请使用 ${expected}`); }
async function html(request: Request, env: Env, assetPath: string): Promise<Response> {
  const asset = await env.ASSETS.fetch(new Request(new URL(assetPath, request.url), { method: request.method }));
  const headers = new Headers(asset.headers);
  headers.set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(asset.body, { status: asset.status, headers });
}
export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    if (url.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 308);
    }
    const control = env.CONTROL.getByName("control");
    try {
      if (path === "/api/login") {
        method(request, "POST"); requireOrigin(request);
        const input = await readJson(request);
        if (typeof input.username !== "string" || typeof input.password !== "string" || input.username.length > 64 || input.password.length > 128) throw new HttpError(400, "账号或密码格式错误");
        const result = await control.login(input.username, input.password, await digest(observedIP(request) ?? "local"));
        if (result.status === 503) return json({ error: "请先配置管理员账号和至少 12 字符的密码" }, 503);
        if (result.status === 429) return json({ error: "尝试次数过多，请在 5 分钟后重试" }, 429, { "Retry-After": "300" });
        if (result.status !== 200 || !result.token) return json({ error: "账号或密码错误" }, 401);
        return json({ ok: true, username: result.username, csrfToken: result.csrfToken }, 200, { "Set-Cookie": sessionCookie(request, result.token) });
      }
      if (path === "/api/ip") { method(request, "GET"); return json({ ip: observedIP(request) }); }
      if (path === "/api/install") {
        method(request, "POST");
        const input = await readJson(request, 1024);
        if (typeof input.ticket !== "string" || !/^[a-f0-9]{64}$/.test(input.ticket)) throw new HttpError(400, "安装凭据格式错误");
        const grant = await control.consumeInstall(input.ticket);
        if (!grant) throw new HttpError(410, "安装命令已使用或已过期，请登录后重新生成");
        return new Response(installationScript(url.origin, grant.server.id, grant.token), {
          headers: { "Content-Type": "text/x-shellscript; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
        });
      }
      const heartbeat = /^\/api\/heartbeat\/([a-zA-Z0-9_-]{1,64})$/.exec(path);
      if (heartbeat) {
        method(request, "POST");
        const bearer = request.headers.get("Authorization") ?? "";
        if (!/^Bearer [A-Za-z0-9._~-]{24,256}$/.test(bearer)) throw new HttpError(401, "探针认证失败");
        const snapshot = await control.snapshot(heartbeat[1]);
        if (!snapshot.server || !equalHash(await digest(bearer.slice(7)), snapshot.server.tokenHash)) throw new HttpError(401, "探针认证失败");
        const ips = withObservedIP(addresses(await readJson(request, 2048, true)), observedIP(request));
        if (!await env.MONITORS.getByName(snapshot.server.id).heartbeat(snapshot.server, !!snapshot.bark.url, ips)) throw new HttpError(401, "探针已停用");
        return json({ ok: true });
      }
      if (path.startsWith("/api/")) {
        const session = await adminSession(request, env, request.method !== "GET");
        if (path === "/api/session") { method(request, "GET"); return json({ username: session.username, csrfToken: session.csrfToken }); }
        if (path === "/api/logout") {
          method(request, "POST"); await control.logout(session.token);
          return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(request, "", 0) });
        }
        if (path === "/api/status") {
          method(request, "GET");
          const { servers: configs, bark } = await control.list();
          const servers = [];
          for (const config of configs) servers.push(await env.MONITORS.getByName(config.id).status(config, !!bark.url));
          return json({ servers, now: Date.now(), barkEnabled: !!bark.url });
        }
        if (path === "/api/clients") {
          method(request, "POST");
          const result = await control.create(await readJson(request));
          if ("error" in result) throw new HttpError(400, result.error ?? "创建失败");
          const { server, ticket, expiresAt } = result;
          await env.MONITORS.getByName(server.id).status(server, !!(await control.snapshot(server.id)).bark.url);
          return json({ server: { id: server.id, name: server.name, timeoutSeconds: server.timeoutSeconds }, installCommand: installationCommand(url.origin, ticket), installExpiresAt: expiresAt }, 201);
        }
        const install = /^\/api\/clients\/([a-zA-Z0-9_-]{1,64})\/install$/.exec(path);
        if (install) {
          method(request, "POST");
          const result = await control.issueInstall(install[1]);
          if (!result) throw new HttpError(404, "客户端不存在");
          return json({ installCommand: installationCommand(url.origin, result.ticket), installExpiresAt: result.expiresAt });
        }
        const client = /^\/api\/clients\/([a-zA-Z0-9_-]{1,64})$/.exec(path);
        if (client) {
          method(request, "DELETE");
          if (!await control.remove(client[1])) throw new HttpError(404, "客户端不存在");
          await env.MONITORS.getByName(client[1]).disable();
          return json({ ok: true });
        }
        if (path === "/api/settings") {
          if (request.method === "GET") return json(await control.settings());
          method(request, "PUT");
          const result = await control.saveSettings(await readJson(request));
          if ("error" in result) throw new HttpError(400, result.error ?? "保存失败");
          return json(result);
        }
        if (path === "/api/bark/test") {
          method(request, "POST");
          const { bark } = await control.list();
          if (!bark.url) throw new HttpError(400, "请先设置 Bark 地址");
          try { await sendBark(bark, "探针推送测试", "Bark 推送连接正常"); }
          catch { return json({ error: "Bark 推送失败，请检查设备地址及 Bark 服务" }, 502); }
          return json({ ok: true });
        }
        throw new HttpError(404, "接口不存在");
      }
      if (request.method !== "GET" && request.method !== "HEAD") throw new HttpError(405, "请使用 GET");
      if (path === "/login" || path === "/login.html") return html(request, env, "/login.html");
      if (path === "/" || path === "/index.html") {
        try { await adminSession(request, env); }
        catch { return new Response(null, { status: 302, headers: { Location: "/login", "Cache-Control": "no-store" } }); }
        return html(request, env, "/index.html");
      }
      throw new HttpError(404, "页面不存在");
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, error.status);
      console.error(JSON.stringify({ event: "request_failed" }));
      return json({ error: "服务暂时不可用" }, 503);
    }
  },
  async scheduled(_controller, env): Promise<void> {
    const control = env.CONTROL.getByName("control");
    await control.prune();
    const { servers, bark } = await control.list();
    for (const config of servers) await env.MONITORS.getByName(config.id).status(config, !!bark.url);
  }
} satisfies ExportedHandler<Env>;
