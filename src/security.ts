import { HttpError } from "./config";

export function randomToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
}
export async function digest(value: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))), byte => byte.toString(16).padStart(2, "0")).join("");
}
export function equalHash(a: string, b: string): boolean {
  return a.length === b.length && crypto.subtle.timingSafeEqual(new TextEncoder().encode(a), new TextEncoder().encode(b));
}
export async function passwordHash(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100_000, hash: "SHA-256" }, key, 256);
  return Array.from(new Uint8Array(bits), byte => byte.toString(16).padStart(2, "0")).join("");
}
function cookieName(request: Request): string { return new URL(request.url).protocol === "https:" ? "__Host-probe_session" : "probe_session"; }
export function sessionCookie(request: Request, token: string, maxAge = 43200): string {
  return `${cookieName(request)}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${new URL(request.url).protocol === "https:" ? "; Secure" : ""}`;
}
export function sessionToken(request: Request): string | null {
  const name = cookieName(request);
  for (const cookie of (request.headers.get("Cookie") ?? "").split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name && /^[a-f0-9]{64}$/.test(value.join("="))) return value.join("=");
  }
  return null;
}
export function requireOrigin(request: Request): void {
  if (request.headers.get("Origin") !== new URL(request.url).origin) throw new HttpError(403, "请求来源无效");
}
