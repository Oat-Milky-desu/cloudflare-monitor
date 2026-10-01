import { isIP } from "node:net";

export type ServerDefinition = { id: string; name: string; tokenHash: string; timeoutSeconds: number; createdAt: number };
export type BarkSettings = { url: string; group: string };
export type Addresses = { ipv4?: string | null; ipv6?: string | null };
export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export function clientInput(value: Record<string, unknown>): { name: string; timeoutSeconds: number } {
  const name = typeof value.name === "string" ? value.name.trim() : "";
  const timeoutSeconds = value.timeoutSeconds ?? 120;
  if (!name || name.length > 100) throw new HttpError(400, "客户端名称须为 1–100 字符");
  if (typeof timeoutSeconds !== "number" || !Number.isInteger(timeoutSeconds) || timeoutSeconds < 60 || timeoutSeconds > 86400) throw new HttpError(400, "超时须为 60–86400 秒整数");
  return { name, timeoutSeconds };
}
export function barkUrl(raw: string): URL | null {
  if (!raw.trim()) return null;
  let url: URL;
  try { url = new URL(raw); } catch { throw new HttpError(400, "Bark 地址格式错误"); }
  if (raw.length > 2048 || url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname === "/") throw new HttpError(400, "Bark 须为 HTTPS 设备推送地址，不含查询参数或账号密码");
  return url;
}
export function maskedBarkUrl(raw: string): string {
  const url = barkUrl(raw);
  return url ? `${url.origin}/••••••` : "";
}
export function addresses(value: Record<string, unknown>): Addresses {
  const result: Addresses = {};
  for (const [key, family] of [["ipv4", 4], ["ipv6", 6]] as const) {
    if (!(key in value)) continue;
    const ip = value[key];
    if (ip !== null && (typeof ip !== "string" || isIP(ip) !== family)) throw new HttpError(400, `${key} 地址格式错误`);
    result[key] = ip as string | null;
  }
  return result;
}
export function observedIP(request: Request): string | null {
  const ip = request.headers.get("CF-Connecting-IP") ?? "";
  return isIP(ip) ? ip : null;
}
export function withObservedIP(value: Addresses, ip: string | null): Addresses {
  return ip ? { ...value, [isIP(ip) === 4 ? "ipv4" : "ipv6"]: ip } : value;
}
export async function readJson(request: Request, limit = 4096, allowEmpty = false): Promise<Record<string, unknown>> {
  if (Number(request.headers.get("Content-Length")) > limit) throw new HttpError(413, "请求内容过大");
  if (!request.body) {
    if (allowEmpty) return {};
    throw new HttpError(400, "请求内容为空");
  }
  if (!(request.headers.get("Content-Type") ?? "").toLowerCase().startsWith("application/json")) throw new HttpError(415, "请使用 JSON 请求");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new HttpError(413, "请求内容过大");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  if (!size && allowEmpty) return {};
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
  let input: unknown;
  try { input = JSON.parse(new TextDecoder().decode(data)); } catch { throw new HttpError(400, "JSON 格式错误"); }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new HttpError(400, "请求须为 JSON 对象");
  return input as Record<string, unknown>;
}
