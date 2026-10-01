import { exports, env } from "cloudflare:workers";
import { reset, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "test-password-at-least-12";
const ORIGIN = "https://probe.example";
const app = exports.default as { fetch(request: Request): Promise<Response> };
const fetchMock = vi.fn<typeof fetch>();

type Json = Record<string, unknown>;
type AdminSession = { cookie: string; csrfToken: string };
type CreatedClient = {
  server: { id: string; name: string; timeoutSeconds: number };
  installCommand: string;
  installExpiresAt: number;
};

function request(path: string, init: RequestInit = {}, cfConnectingIp?: string): Promise<Response> {
  const headers = new Headers(init.headers);
  if (cfConnectingIp) headers.set("CF-Connecting-IP", cfConnectingIp);
  return app.fetch(new Request(`${ORIGIN}${path}`, { ...init, headers, redirect: "manual" }));
}

function jsonRequest(method: string, value: unknown): RequestInit {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value),
  };
}

async function responseJson<T extends Json = Json>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

async function login(password = ADMIN_PASSWORD, origin: string | null = ORIGIN, cfConnectingIp?: string): Promise<Response> {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (origin) headers.set("Origin", origin);
  return request("/api/login", {
    method: "POST",
    headers,
    body: JSON.stringify({ username: ADMIN_USERNAME, password }),
  }, cfConnectingIp);
}

async function adminSession(): Promise<AdminSession> {
  const response = await login();
  expect(response.status).toBe(200);
  const payload = await responseJson<{ csrfToken: string }>(response);
  const setCookie = response.headers.get("Set-Cookie") ?? "";
  const cookie = setCookie.split(";", 1)[0] ?? "";
  expect(cookie).toMatch(/^__Host-probe_session=[a-f0-9]{64}$/);
  return { cookie, csrfToken: payload.csrfToken };
}

function adminRequest(
  session: AdminSession,
  path: string,
  init: RequestInit = {},
  security: { origin?: string | null; csrfToken?: string | null } = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Cookie", session.cookie);
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    const origin = security.origin === undefined ? ORIGIN : security.origin;
    const csrfToken = security.csrfToken === undefined ? session.csrfToken : security.csrfToken;
    if (origin) headers.set("Origin", origin);
    else headers.delete("Origin");
    if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    else headers.delete("X-CSRF-Token");
  }
  return request(path, { ...init, headers });
}

async function createClient(session: AdminSession, name = "edge probe", timeoutSeconds = 120): Promise<CreatedClient> {
  const response = await adminRequest(session, "/api/clients", jsonRequest("POST", { name, timeoutSeconds }));
  expect(response.status).toBe(201);
  return responseJson<CreatedClient>(response);
}

function installTicket(command: string): string {
  const match = /--data '([^']+)'/.exec(command);
  expect(match?.[1]).toBeTruthy();
  const payload = JSON.parse(match![1]!) as { ticket?: unknown };
  expect(payload.ticket).toMatch(/^[a-f0-9]{64}$/);
  return payload.ticket as string;
}

function decodeBase64Utf8(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assignment(script: string, name: "CONFIG_B64" | "AGENT_B64" | "SERVICE_B64"): string {
  const match = new RegExp(`^${name}='([A-Za-z0-9+/=]+)'$`, "m").exec(script);
  expect(match?.[1]).toBeTruthy();
  return match![1]!;
}

function controlStub() {
  return env.CONTROL.getByName("control");
}

function monitorStub(id: string) {
  return env.MONITORS.getByName(id);
}

async function expireMonitor(id: string, seconds = 120): Promise<void> {
  await runInDurableObject(monitorStub(id), (_instance, state) => {
    state.storage.sql.exec("UPDATE monitor SET last_seen=? WHERE singleton=1", Date.now() - seconds * 1000 - 1);
  });
}

async function monitorOutbox(id: string): Promise<Array<{ title: string; body: string; attempts: number; next_attempt: number }>> {
  return runInDurableObject(monitorStub(id), (_instance, state) =>
    state.storage.sql
      .exec<{ title: string; body: string; attempts: number; next_attempt: number }>(
        "SELECT title,body,attempts,next_attempt FROM outbox ORDER BY seq",
      )
      .toArray(),
  );
}

async function expireInstallTicket(ticket: string): Promise<void> {
  const ticketHash = await sha256(ticket);
  await runInDurableObject(controlStub(), (_instance, state) => {
    state.storage.sql.exec("UPDATE install_grants SET expires_at=? WHERE ticket_hash=?", Date.now() - 1, ticketHash);
  });
}

async function expireAdminSession(cookie: string): Promise<void> {
  const token = cookie.slice("__Host-probe_session=".length);
  const tokenHash = await sha256(token);
  await runInDurableObject(controlStub(), (_instance, state) => {
    state.storage.sql.exec("UPDATE sessions SET expires_at=? WHERE token_hash=?", Date.now() - 1, tokenHash);
  });
}

function freshBarkSuccess(): Response {
  return new Response('{"code":200}', { headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockRejectedValue(new Error("Unexpected outbound request"));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await reset();
});

describe("admin access", () => {
  it("serves the login page and redirects protected dashboard paths without a session", async () => {
    const loginPage = await request("/login");
    expect(loginPage.status).toBe(200);
    expect(loginPage.headers.get("Content-Security-Policy")).toContain("default-src 'none'");

    for (const path of ["/", "/index.html"]) {
      const response = await request(path);
      expect(response.status).toBe(302);
      expect(response.headers.get("Location")).toBe("/login");
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires a same-origin JSON login request", async () => {
    expect((await login(ADMIN_PASSWORD, null)).status).toBe(403);
    const wrongOrigin = await login(ADMIN_PASSWORD, "https://attacker.example");
    expect(wrongOrigin.status).toBe(403);

    const unsupportedType = await request("/api/login", {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "text/plain" },
      body: "{}",
    });
    expect(unsupportedType.status).toBe(415);
  });

  it("rejects incorrect credentials and throttles the sixth failure from one IP", async () => {
    const rateLimitedIp = "198.51.100.17";
    expect((await login("wrong-password-at-least-12", ORIGIN, rateLimitedIp)).status).toBe(401);
    for (let attempt = 0; attempt < 4; attempt++) {
      expect((await login("wrong-password-at-least-12", ORIGIN, rateLimitedIp)).status).toBe(401);
    }
    const throttled = await login("wrong-password-at-least-12", ORIGIN, rateLimitedIp);
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get("Retry-After")).toBe("300");
    expect((await login("wrong-password-at-least-12", ORIGIN, "198.51.100.18")).status).toBe(401);
  });

  it("sets a secure host-only session cookie and exposes a CSRF token to the session owner", async () => {
    const response = await login();
    expect(response.status).toBe(200);
    const payload = await responseJson<{ username: string; csrfToken: string }>(response);
    expect(payload.username).toBe(ADMIN_USERNAME);
    expect(payload.csrfToken).toMatch(/^[a-f0-9]{64}$/);
    const cookie = response.headers.get("Set-Cookie") ?? "";
    expect(cookie).toMatch(/^__Host-probe_session=[a-f0-9]{64};/);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/");

    const session = { cookie: cookie.split(";", 1)[0]!, csrfToken: payload.csrfToken };
    const current = await adminRequest(session, "/api/session");
    expect(current.status).toBe(200);
    expect(await responseJson(current)).toEqual({ username: ADMIN_USERNAME, csrfToken: payload.csrfToken });
  });

  it("requires Origin and the session CSRF token on every admin mutation", async () => {
    const session = await adminSession();
    const mutations: Array<[string, RequestInit]> = [
      ["/api/logout", { method: "POST" }],
      ["/api/clients", jsonRequest("POST", { name: "blocked" })],
      ["/api/clients/missing/install", { method: "POST" }],
      ["/api/clients/missing", { method: "DELETE" }],
      ["/api/settings", jsonRequest("PUT", { barkGroup: "Ops" })],
      ["/api/bark/test", { method: "POST" }],
    ];

    for (const [path, init] of mutations) {
      expect((await adminRequest(session, path, init, { origin: null })).status).toBe(403);
      expect((await adminRequest(session, path, init, { csrfToken: "wrong-csrf-token" })).status).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("expires a revoked or timed-out session and clears the cookie on logout", async () => {
    const session = await adminSession();
    const logout = await adminRequest(session, "/api/logout", { method: "POST" });
    expect(logout.status).toBe(200);
    expect(logout.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect((await adminRequest(session, "/api/session")).status).toBe(401);

    const expired = await adminSession();
    await expireAdminSession(expired.cookie);
    expect((await adminRequest(expired, "/api/session")).status).toBe(401);
  });

  it("keeps API data behind an authenticated session", async () => {
    expect((await request("/api/status")).status).toBe(401);
    expect((await request("/api/settings")).status).toBe(401);
    const response = await request("/api/status", { headers: { Cookie: "__Host-probe_session=invalid" } });
    expect(response.status).toBe(401);
  });
});

describe("client installation lifecycle", () => {
  it("rejects blank, overlong, and invalid-timeout client input", async () => {
    const session = await adminSession();
    for (const input of [
    ["blank name", { name: "   " }],
    ["overlong name", { name: "x".repeat(101) }],
    ["timeout below minimum", { name: "probe", timeoutSeconds: 59 }],
    ["fractional timeout", { name: "probe", timeoutSeconds: 60.5 }],
    ]) {
      const response = await adminRequest(session, "/api/clients", jsonRequest("POST", input[1]));
      expect(response.status).toBe(400);
    }
  });

  it("creates a client without returning its bearer token in the response or status", async () => {
    const session = await adminSession();
    const created = await createClient(session, "home gateway", 600);
    expect(created.server).toEqual({ id: expect.stringMatching(/^node-[a-f0-9]{12}$/), name: "home gateway", timeoutSeconds: 600 });
    expect(created.installExpiresAt).toBeGreaterThan(Date.now());
    expect(created.installCommand).toContain("/api/install");
    expect(created.installCommand).not.toContain("token");

    const status = await adminRequest(session, "/api/status");
    expect(status.status).toBe(200);
    const statusText = JSON.stringify(await responseJson(status));
    expect(statusText).toContain(created.server.id);
    expect(statusText).not.toContain("client_token");
    expect(statusText).not.toContain("tokenHash");
  });

  it("consumes a one-time install ticket and embeds valid config and source files", async () => {
    const session = await adminSession();
    const created = await createClient(session, "installer test");
    const ticket = installTicket(created.installCommand);
    const installed = await request("/api/install", jsonRequest("POST", { ticket }));
    expect(installed.status).toBe(200);
    expect(installed.headers.get("Content-Type")).toContain("text/x-shellscript");
    expect(installed.headers.get("Cache-Control")).toBe("no-store");
    const script = await installed.text();

    const configData = assignment(script, "CONFIG_B64");
    const config = JSON.parse(decodeBase64Utf8(configData)) as {
      workerUrl: string; serverId: string; token: string; intervalSeconds: number; requestTimeoutSeconds: number;
    };
    expect(config).toEqual({
      workerUrl: ORIGIN,
      serverId: created.server.id,
      token: expect.stringMatching(/^[a-f0-9]{64}$/),
      intervalSeconds: 30,
      requestTimeoutSeconds: 10,
    });

    const agent = decodeBase64Utf8(assignment(script, "AGENT_B64"));
    const service = decodeBase64Utf8(assignment(script, "SERVICE_B64"));
    expect(agent).toContain("#!/usr/bin/env python3");
    expect(agent).toContain("def post_heartbeat(");
    expect(service).toContain("Description=Cloudflare Workers server probe");
    expect(script).toContain("*__CONFIG_BASE64__*|*__AGENT_BASE64__*|*__SERVICE_BASE64__*");
    expect(script).not.toMatch(/^(?:CONFIG|AGENT|SERVICE)_B64='__(?:CONFIG|AGENT|SERVICE)_BASE64__'$/m);

    const secondUse = await request("/api/install", jsonRequest("POST", { ticket }));
    expect(secondUse.status).toBe(410);
    expect(JSON.stringify(await responseJson(await adminRequest(session, "/api/status")))).not.toContain(config.token);
  });

  it("rejects expired and malformed public install tickets", async () => {
    expect((await request("/api/install", jsonRequest("POST", { ticket: "bad" }))).status).toBe(400);
    const session = await adminSession();
    const created = await createClient(session);
    const ticket = installTicket(created.installCommand);
    await expireInstallTicket(ticket);
    expect((await request("/api/install", jsonRequest("POST", { ticket }))).status).toBe(410);
  });

  it("revokes an unused ticket and rotates a consumed client token only when the new ticket is used", async () => {
    const session = await adminSession();
    const created = await createClient(session, "rotation test");
    const originalTicket = installTicket(created.installCommand);
    const firstInstall = await request("/api/install", jsonRequest("POST", { ticket: originalTicket }));
    const firstConfig = JSON.parse(decodeBase64Utf8(assignment(await firstInstall.text(), "CONFIG_B64"))) as { token: string };

    const reissued = await adminRequest(session, `/api/clients/${created.server.id}/install`, { method: "POST" });
    expect(reissued.status).toBe(200);
    const newCommand = (await responseJson<{ installCommand: string }>(reissued)).installCommand;
    const newTicket = installTicket(newCommand);
    expect((await request("/api/install", jsonRequest("POST", { ticket: originalTicket }))).status).toBe(410);

    const stillCurrent = await request(`/api/heartbeat/${created.server.id}`, {
      method: "POST", headers: { Authorization: `Bearer ${firstConfig.token}` },
    });
    expect(stillCurrent.status).toBe(200);

    const secondInstall = await request("/api/install", jsonRequest("POST", { ticket: newTicket }));
    expect(secondInstall.status).toBe(200);
    const secondConfig = JSON.parse(decodeBase64Utf8(assignment(await secondInstall.text(), "CONFIG_B64"))) as { token: string };
    expect(secondConfig.token).not.toBe(firstConfig.token);
    expect((await request(`/api/heartbeat/${created.server.id}`, {
      method: "POST", headers: { Authorization: `Bearer ${firstConfig.token}` },
    })).status).toBe(401);
    expect((await request(`/api/heartbeat/${created.server.id}`, {
      method: "POST", headers: { Authorization: `Bearer ${secondConfig.token}` },
    })).status).toBe(200);
  });

  it("deletes a client, rejects its old heartbeat, and clears pending monitor alarms", async () => {
    const session = await adminSession();
    const settings = await adminRequest(session, "/api/settings", jsonRequest("PUT", {
      barkUrl: "https://api.day.app/test-device-key", barkGroup: "Ops",
    }));
    expect(settings.status).toBe(200);
    const created = await createClient(session, "delete test", 60);
    const ticket = installTicket(created.installCommand);
    const installed = await request("/api/install", jsonRequest("POST", { ticket }));
    const config = JSON.parse(decodeBase64Utf8(assignment(await installed.text(), "CONFIG_B64"))) as { token: string };
    await request(`/api/heartbeat/${created.server.id}`, { method: "POST", headers: { Authorization: `Bearer ${config.token}` } });
    await expireMonitor(created.server.id, 60);
    fetchMock.mockRejectedValueOnce(new Error("Bark unavailable"));
    await runDurableObjectAlarm(monitorStub(created.server.id));
    expect(await monitorOutbox(created.server.id)).toHaveLength(1);

    const removed = await adminRequest(session, `/api/clients/${created.server.id}`, { method: "DELETE" });
    expect(removed.status).toBe(200);
    expect(await monitorOutbox(created.server.id)).toHaveLength(0);
    expect(await runDurableObjectAlarm(monitorStub(created.server.id))).toBe(false);
    expect((await request(`/api/heartbeat/${created.server.id}`, {
      method: "POST", headers: { Authorization: `Bearer ${config.token}` },
    })).status).toBe(401);
  });
});

describe("heartbeat and status", () => {
  async function installedClient(session: AdminSession, name = "heartbeat test") {
    const created = await createClient(session, name);
    const ticket = installTicket(created.installCommand);
    const response = await request("/api/install", jsonRequest("POST", { ticket }));
    expect(response.status).toBe(200);
    const config = JSON.parse(decodeBase64Utf8(assignment(await response.text(), "CONFIG_B64"))) as { token: string };
    return { ...created, token: config.token };
  }

  it("accepts only an active client bearer token and POST method", async () => {
    const session = await adminSession();
    const client = await installedClient(session);
    expect((await request(`/api/heartbeat/${client.server.id}`, { method: "POST" })).status).toBe(401);
    expect((await request(`/api/heartbeat/${client.server.id}`, {
      method: "POST", headers: { Authorization: `Bearer ${"x".repeat(24)}` },
    })).status).toBe(401);
    expect((await request(`/api/heartbeat/${client.server.id}`, {
      method: "GET", headers: { Authorization: `Bearer ${client.token}` },
    })).status).toBe(405);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("stores IPv4 and IPv6 and gives Cloudflare's observed address priority", async () => {
    const session = await adminSession();
    const client = await installedClient(session);
    const heartbeat = await request(`/api/heartbeat/${client.server.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${client.token}` },
      body: JSON.stringify({ ipv4: "203.0.113.8", ipv6: "2001:db8::8" }),
    }, "198.51.100.77");
    expect(heartbeat.status).toBe(200);

    const status = await adminRequest(session, "/api/status");
    const body = await responseJson<{ servers: Array<Json> }>(status);
    expect(body.servers).toEqual([expect.objectContaining({
      id: client.server.id,
      status: "online",
      ipv4: "198.51.100.77",
      ipv6: "2001:db8::8",
    })]);
  });

  it("rejects invalid address input without changing monitor state", async () => {
    const session = await adminSession();
    const client = await installedClient(session);
    const response = await request(`/api/heartbeat/${client.server.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${client.token}` },
      body: JSON.stringify({ ipv4: "not-an-ip" }),
    });
    expect(response.status).toBe(400);
    const body = await responseJson<{ servers: Array<Json> }>(await adminRequest(session, "/api/status"));
    expect(body.servers).toEqual([expect.objectContaining({ status: "waiting", lastSeen: null })]);
  });

  it("keeps empty heartbeat bodies compatible and records the observed address", async () => {
    const session = await adminSession();
    const client = await installedClient(session);
    const heartbeat = await request(`/api/heartbeat/${client.server.id}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${client.token}` },
    }, "2001:db8::77");
    expect(heartbeat.status).toBe(200);
    const body = await responseJson<{ servers: Array<Json> }>(await adminRequest(session, "/api/status"));
    expect(body.servers).toEqual([expect.objectContaining({ ipv4: null, ipv6: "2001:db8::77", status: "online" })]);
  });

  it("reports the observed IP without requiring an admin session", async () => {
    expect(await responseJson(await request("/api/ip", {}, "192.0.2.42"))).toEqual({ ip: "192.0.2.42" });
    expect(await responseJson(await request("/api/ip"))).toEqual({ ip: null });
  });
});

describe("Bark settings and durable notifications", () => {
  it("masks the Bark device key, preserves omitted settings, and rejects HTTP URLs", async () => {
    const session = await adminSession();
    const secretUrl = "https://api.day.app/private-device-key";
    const saved = await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkUrl: secretUrl, barkGroup: "Operations" }));
    expect(saved.status).toBe(200);
    expect(await responseJson(saved)).toEqual({ barkEnabled: true, barkUrl: "https://api.day.app/••••••", barkGroup: "Operations" });

    const changedGroup = await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkGroup: "Infra" }));
    expect(await responseJson(changedGroup)).toEqual({ barkEnabled: true, barkUrl: "https://api.day.app/••••••", barkGroup: "Infra" });
    const emptyGroup = await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkGroup: "" }));
    expect(emptyGroup.status).toBe(200);
    expect((await responseJson(emptyGroup)).barkGroup).toBe("Infra");
    expect(JSON.stringify(await responseJson(await adminRequest(session, "/api/status")))).not.toContain("private-device-key");

    const invalid = await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkUrl: "http://api.day.app/device-key" }));
    expect(invalid.status).toBe(400);
    const afterInvalid = await responseJson(await adminRequest(session, "/api/settings"));
    expect(afterInvalid.barkGroup).toBe("Infra");
    expect(JSON.stringify(afterInvalid)).not.toContain("private-device-key");
  });

  it("uses a fresh mocked Bark response for every test request and hides remote error details", async () => {
    const session = await adminSession();
    await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkUrl: "https://api.day.app/mock-key" }));
    fetchMock.mockImplementation(async () => freshBarkSuccess());

    const first = await adminRequest(session, "/api/bark/test", { method: "POST" });
    const second = await adminRequest(session, "/api/bark/test", { method: "POST" });
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstBarkResponse = await fetchMock.mock.results[0]?.value;
    const secondBarkResponse = await fetchMock.mock.results[1]?.value;
    expect(firstBarkResponse).not.toBe(secondBarkResponse);
    const sent = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as Json;
    expect(sent).toEqual(expect.objectContaining({ title: "探针推送测试", group: "服务器探针" }));

    fetchMock.mockImplementationOnce(async () => new Response("device-secret-detail", { status: 502 }));
    const failed = await adminRequest(session, "/api/bark/test", { method: "POST" });
    expect(failed.status).toBe(502);
    expect(await failed.text()).not.toContain("device-secret-detail");
  });

  it("detects a first-heartbeat timeout and queues one offline notice", async () => {
    const session = await adminSession();
    const client = await createClient(session, "first heartbeat timeout", 60);
    await adminRequest(session, "/api/status");
    await runInDurableObject(monitorStub(client.server.id), (_instance, state) => {
      state.storage.sql.exec("UPDATE monitor SET monitored_since=? WHERE singleton=1", Date.now() - 60_001);
    });
    expect(await runDurableObjectAlarm(monitorStub(client.server.id))).toBe(true);

    const status = await responseJson<{ servers: Array<Json> }>(await adminRequest(session, "/api/status"));
    expect(status.servers).toEqual([expect.objectContaining({ status: "offline", lastSeen: null })]);
    expect(await monitorOutbox(client.server.id)).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends one offline notice and one recovery notice as state changes", async () => {
    const session = await adminSession();
    await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkUrl: "https://api.day.app/test-key" }));
    const client = await createClient(session, "recovery test", 60);
    const ticket = installTicket(client.installCommand);
    const config = JSON.parse(decodeBase64Utf8(assignment(await (await request("/api/install", jsonRequest("POST", { ticket }))).text(), "CONFIG_B64"))) as { token: string };
    fetchMock.mockImplementation(async () => freshBarkSuccess());

    const heartbeat = () => request(`/api/heartbeat/${client.server.id}`, {
      method: "POST", headers: { Authorization: `Bearer ${config.token}` },
    });
    await heartbeat();
    await expireMonitor(client.server.id, 60);
    await heartbeat();
    expect(await monitorOutbox(client.server.id)).toEqual([
      expect.objectContaining({ title: "服务器离线" }),
      expect.objectContaining({ title: "服务器恢复在线" }),
    ]);
    await runInDurableObject(monitorStub(client.server.id), (_instance, state) => {
      state.storage.sql.exec("UPDATE outbox SET next_attempt=?", Date.now() - 1);
    });
    expect(await runDurableObjectAlarm(monitorStub(client.server.id))).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(await monitorOutbox(client.server.id)).toHaveLength(0);
  });

  it("retains a failed notice and retries it after the backoff deadline", async () => {
    const session = await adminSession();
    await adminRequest(session, "/api/settings", jsonRequest("PUT", { barkUrl: "https://api.day.app/retry-key" }));
    const client = await createClient(session, "retry test", 60);
    const ticket = installTicket(client.installCommand);
    const install = await request("/api/install", jsonRequest("POST", { ticket }));
    const config = JSON.parse(decodeBase64Utf8(assignment(await install.text(), "CONFIG_B64"))) as { token: string };
    fetchMock.mockImplementationOnce(async () => new Response("unavailable", { status: 503 }));

    await request(`/api/heartbeat/${client.server.id}`, { method: "POST", headers: { Authorization: `Bearer ${config.token}` } });
    await expireMonitor(client.server.id, 60);
    expect(await runDurableObjectAlarm(monitorStub(client.server.id))).toBe(true);
    const pending = await monitorOutbox(client.server.id);
    expect(pending).toHaveLength(1);
    expect(pending[0]).toEqual(expect.objectContaining({ title: "服务器离线", attempts: 1 }));
    expect(pending[0]!.next_attempt).toBeGreaterThan(Date.now());

    await runInDurableObject(monitorStub(client.server.id), (_instance, state) => {
      state.storage.sql.exec("UPDATE outbox SET next_attempt=?", Date.now() - 1);
    });
    fetchMock.mockImplementation(async () => freshBarkSuccess());
    expect(await runDurableObjectAlarm(monitorStub(client.server.id))).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(await monitorOutbox(client.server.id)).toHaveLength(0);
  });
});
