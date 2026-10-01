import { DurableObject } from "cloudflare:workers";
import { barkUrl, clientInput, HttpError, maskedBarkUrl, type BarkSettings, type ServerDefinition } from "./config";
import { digest, equalHash, passwordHash, randomToken } from "./security";

type ClientRow = { id: string; name: string; token_hash: string; timeout_seconds: number; created_at: number };
type AdminRow = { username: string; salt: string; password_hash: string };
type SessionRow = { username: string; csrf: string; expires_at: number };
type GrantRow = { client_id: string; client_token: string; expires_at: number };
const SESSION_MS = 12 * 60 * 60 * 1000;
const INSTALL_MS = 10 * 60 * 1000;
function definition(row: ClientRow): ServerDefinition {
  return { id: row.id, name: row.name, tokenHash: row.token_hash, timeoutSeconds: row.timeout_seconds, createdAt: row.created_at };
}
export class ControlPlane extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL, timeout_seconds INTEGER NOT NULL, created_at INTEGER NOT NULL)`);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS admin (singleton INTEGER PRIMARY KEY CHECK(singleton=1), username TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL)`);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL)`);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS install_grants (ticket_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL UNIQUE, client_token TEXT NOT NULL, expires_at INTEGER NOT NULL)`);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1), bark_url TEXT NOT NULL DEFAULT '', bark_group TEXT NOT NULL DEFAULT '服务器探针')`);
    this.ctx.storage.sql.exec(`INSERT OR IGNORE INTO settings(singleton) VALUES(1)`);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS login_limits (ip_hash TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires_at INTEGER NOT NULL)`);
    this.ctx.blockConcurrencyWhile(async () => {
      const password = this.env.ADMIN_PASSWORD;
      const username = this.env.ADMIN_USERNAME;
      if (!password || password.length < 12 || password.length > 128 || !username?.trim() || username.length > 64) {
        this.ctx.storage.sql.exec("DELETE FROM sessions");
        return;
      }
      const stored = this.ctx.storage.sql.exec<AdminRow>("SELECT * FROM admin WHERE singleton=1").toArray()[0];
      const salt = stored?.salt ?? randomToken();
      const hash = await passwordHash(password, salt);
      if (!stored || stored.username !== username || !equalHash(stored.password_hash, hash)) {
        this.ctx.storage.transactionSync(() => {
          this.ctx.storage.sql.exec("INSERT OR REPLACE INTO admin VALUES(1,?,?,?)", username, salt, hash);
          this.ctx.storage.sql.exec("DELETE FROM sessions");
        });
      }
    });
  }
  async login(username: string, password: string, ipHash: string) {
    if (!this.env.ADMIN_PASSWORD || this.env.ADMIN_PASSWORD.length < 12 || this.env.ADMIN_PASSWORD.length > 128 || !this.env.ADMIN_USERNAME?.trim() || this.env.ADMIN_USERNAME.length > 64) return { status: 503 as const };
    const admin = this.ctx.storage.sql.exec<AdminRow>("SELECT * FROM admin WHERE singleton=1").toArray()[0];
    if (!admin) return { status: 503 as const };
    const now = Date.now();
    this.ctx.storage.sql.exec("DELETE FROM login_limits WHERE expires_at<=?", now);
    const limit = this.ctx.storage.sql.exec<{ attempts: number }>("SELECT attempts FROM login_limits WHERE ip_hash=?", ipHash).toArray()[0];
    if (limit && limit.attempts >= 5) return { status: 429 as const };
    this.ctx.storage.sql.exec("INSERT INTO login_limits VALUES(?,1,?) ON CONFLICT(ip_hash) DO UPDATE SET attempts=attempts+1", ipHash, now + 300_000);
    const hash = await passwordHash(password, admin.salt);
    if (!equalHash(await digest(username), await digest(admin.username)) || !equalHash(hash, admin.password_hash)) return { status: 401 as const };
    const token = randomToken();
    const csrf = randomToken();
    const tokenHash = await digest(token);
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM login_limits WHERE ip_hash=?", ipHash);
      this.ctx.storage.sql.exec("DELETE FROM sessions WHERE expires_at<=?", now);
      this.ctx.storage.sql.exec("INSERT INTO sessions VALUES(?,?,?,?)", tokenHash, admin.username, csrf, now + SESSION_MS);
    });
    return { status: 200 as const, token, username: admin.username, csrfToken: csrf };
  }
  async session(token: string) {
    const row = this.ctx.storage.sql.exec<SessionRow>("SELECT username,csrf,expires_at FROM sessions WHERE token_hash=?", await digest(token)).toArray()[0];
    return row && row.expires_at > Date.now() ? { username: row.username, csrfToken: row.csrf } : null;
  }
  async logout(token: string): Promise<void> { this.ctx.storage.sql.exec("DELETE FROM sessions WHERE token_hash=?", await digest(token)); }
  private client(id: string): ServerDefinition | null {
    const row = this.ctx.storage.sql.exec<ClientRow>("SELECT * FROM clients WHERE id=?", id).toArray()[0];
    return row ? definition(row) : null;
  }
  private bark(): BarkSettings {
    const row = this.ctx.storage.sql.exec<{ bark_url: string; bark_group: string }>("SELECT bark_url,bark_group FROM settings WHERE singleton=1").one();
    return { url: row.bark_url, group: row.bark_group };
  }
  snapshot(id: string) { return { server: this.client(id), bark: this.bark() }; }
  list() { return { servers: this.ctx.storage.sql.exec<ClientRow>("SELECT * FROM clients ORDER BY created_at,id").toArray().map(definition), bark: this.bark() }; }
  settings() {
    const bark = this.bark();
    return { barkEnabled: !!bark.url, barkUrl: maskedBarkUrl(bark.url), barkGroup: bark.group };
  }
  saveSettings(input: Record<string, unknown>) {
    const old = this.bark();
    if (input.barkUrl !== undefined && typeof input.barkUrl !== "string") return { error: "Bark 地址格式错误" };
    if (input.barkGroup !== undefined && (typeof input.barkGroup !== "string" || input.barkGroup.length > 80)) return { error: "Bark 分组最多 80 字符" };
    const url = input.barkUrl === undefined ? old.url : (input.barkUrl as string).trim();
    try { barkUrl(url); } catch { return { error: "Bark 须为 HTTPS 设备推送地址，不含查询参数或账号密码" }; }
    const group = typeof input.barkGroup === "string" ? input.barkGroup.trim() || old.group : old.group;
    this.ctx.storage.sql.exec("UPDATE settings SET bark_url=?,bark_group=? WHERE singleton=1", url, group);
    return this.settings();
  }
  async create(input: Record<string, unknown>) {
    let config: ReturnType<typeof clientInput>;
    try { config = clientInput(input); }
    catch (error) {
      if (error instanceof HttpError) return { error: error.message };
      throw error;
    }
    if (this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM clients").one().count >= 100) return { error: "最多支持 100 个客户端" };
    const id = `node-${randomToken().slice(0, 12)}`;
    const token = randomToken();
    const ticket = randomToken();
    const [tokenHash, ticketHash] = await Promise.all([digest(token), digest(ticket)]);
    const now = Date.now();
    const expiresAt = now + INSTALL_MS;
    const inserted = this.ctx.storage.transactionSync(() => {
      if (this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM clients").one().count >= 100) return false;
      this.ctx.storage.sql.exec("INSERT INTO clients VALUES(?,?,?,?,?)", id, config.name, tokenHash, config.timeoutSeconds, now);
      this.ctx.storage.sql.exec("INSERT INTO install_grants VALUES(?,?,?,?)", ticketHash, id, token, expiresAt);
      return true;
    });
    if (!inserted) return { error: "最多支持 100 个客户端" };
    return { server: this.client(id)!, ticket, expiresAt };
  }
  async issueInstall(id: string) {
    if (!this.client(id)) return null;
    const ticket = randomToken();
    const token = randomToken();
    const ticketHash = await digest(ticket);
    const expiresAt = Date.now() + INSTALL_MS;
    if (!this.client(id)) return null;
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO install_grants VALUES(?,?,?,?)", ticketHash, id, token, expiresAt);
    return { ticket, expiresAt };
  }
  async consumeInstall(ticket: string) {
    const ticketHash = await digest(ticket);
    const grant = this.ctx.storage.sql.exec<GrantRow>("SELECT client_id,client_token,expires_at FROM install_grants WHERE ticket_hash=?", ticketHash).toArray()[0];
    if (!grant || grant.expires_at <= Date.now()) return null;
    const tokenHash = await digest(grant.client_token);
    return this.ctx.storage.transactionSync(() => {
      const active = this.ctx.storage.sql.exec<GrantRow>("DELETE FROM install_grants WHERE ticket_hash=? AND expires_at>? RETURNING client_id,client_token,expires_at", ticketHash, Date.now()).toArray()[0];
      const client = active ? this.client(active.client_id) : null;
      if (!active || !client) return null;
      this.ctx.storage.sql.exec("UPDATE clients SET token_hash=? WHERE id=?", tokenHash, client.id);
      return { server: client, token: active.client_token };
    });
  }
  remove(id: string): boolean {
    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM install_grants WHERE client_id=?", id);
      return this.ctx.storage.sql.exec<{ id: string }>("DELETE FROM clients WHERE id=? RETURNING id", id).toArray().length > 0;
    });
  }
  prune(): void {
    const now = Date.now();
    this.ctx.storage.sql.exec("DELETE FROM sessions WHERE expires_at<=?", now);
    this.ctx.storage.sql.exec("DELETE FROM install_grants WHERE expires_at<=?", now);
    this.ctx.storage.sql.exec("DELETE FROM login_limits WHERE expires_at<=?", now);
  }
}
