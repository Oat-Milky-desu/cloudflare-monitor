import { DurableObject } from "cloudflare:workers";
import { type Addresses, type ServerDefinition } from "./config";
import { sendBark } from "./bark";

type StateRow = {
  id: string; name: string; status: "waiting" | "online" | "offline";
  last_seen: number | null; monitored_since: number; timeout_seconds: number;
  ipv4: string | null; ipv6: string | null; disabled: number;
};
type EventRow = { seq: number; title: string; body: string; attempts: number; next_attempt: number };
export class ServerMonitor extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS monitor (
      singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL, name TEXT NOT NULL,
      status TEXT NOT NULL, last_seen INTEGER, monitored_since INTEGER NOT NULL, timeout_seconds INTEGER NOT NULL,
      ipv4 TEXT, ipv6 TEXT, disabled INTEGER NOT NULL DEFAULT 0
    )`);
    const columns = this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(monitor)").toArray().map(column => column.name);
    for (const [name, type] of [["ipv4", "TEXT"], ["ipv6", "TEXT"], ["disabled", "INTEGER NOT NULL DEFAULT 0"]]) {
      if (!columns.includes(name)) this.ctx.storage.sql.exec(`ALTER TABLE monitor ADD COLUMN ${name} ${type}`);
    }
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS outbox (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL
    )`);
  }
  private row(): StateRow | undefined { return this.ctx.storage.sql.exec<StateRow>("SELECT * FROM monitor WHERE singleton=1").toArray()[0]; }
  private event(status: "online" | "offline", row: StateRow, now: number, enabled: boolean): void {
    if (!enabled) return;
    const title = status === "offline" ? "服务器离线" : "服务器恢复在线";
    const body = `${row.name} (${row.id})\n${status === "offline" ? `超过 ${row.timeout_seconds} 秒未收到心跳` : "已重新收到心跳"}\n${new Date(now).toISOString()}`;
    this.ctx.storage.sql.exec("INSERT INTO outbox(title,body,next_attempt) VALUES(?,?,?)", title, body, now);
  }
  private sync(config: ServerDefinition, enabled: boolean, heartbeat: boolean, ips: Addresses = {}): void {
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(`INSERT INTO monitor(singleton,id,name,status,last_seen,monitored_since,timeout_seconds)
        VALUES(1,?,?,'waiting',NULL,?,?) ON CONFLICT(singleton) DO UPDATE SET name=excluded.name,timeout_seconds=excluded.timeout_seconds`,
        config.id, config.name, config.createdAt, config.timeoutSeconds);
      const row = this.row()!;
      if (row.disabled) return;
      if (!enabled) this.ctx.storage.sql.exec("DELETE FROM outbox");
      if (row.status !== "offline" && now >= (row.last_seen ?? row.monitored_since) + row.timeout_seconds * 1000) {
        this.ctx.storage.sql.exec("UPDATE monitor SET status='offline' WHERE singleton=1");
        this.event("offline", row, now, enabled);
        row.status = "offline";
      }
      if (heartbeat) {
        this.ctx.storage.sql.exec("UPDATE monitor SET status='online',last_seen=? WHERE singleton=1", now);
        if (ips.ipv4 !== undefined) this.ctx.storage.sql.exec("UPDATE monitor SET ipv4=? WHERE singleton=1", ips.ipv4);
        if (ips.ipv6 !== undefined) this.ctx.storage.sql.exec("UPDATE monitor SET ipv6=? WHERE singleton=1", ips.ipv6);
        if (row.status === "offline") this.event("online", row, now, enabled);
      }
    });
  }
  private async arm(): Promise<void> {
    const row = this.row();
    if (row?.disabled) { await this.ctx.storage.deleteAlarm(); return; }
    const head = this.ctx.storage.sql.exec<EventRow>("SELECT * FROM outbox ORDER BY seq LIMIT 1").toArray()[0];
    const due = row && row.status !== "offline" ? (row.last_seen ?? row.monitored_since) + row.timeout_seconds * 1000 : Infinity;
    const next = Math.min(due, head?.next_attempt ?? Infinity);
    if (Number.isFinite(next)) await this.ctx.storage.setAlarm(Math.max(Date.now() + 1, next));
    else await this.ctx.storage.deleteAlarm();
  }
  async heartbeat(config: ServerDefinition, barkEnabled: boolean, ips: Addresses): Promise<boolean> {
    if (this.row()?.disabled) return false;
    this.sync(config, barkEnabled, true, ips);
    await this.arm();
    return true;
  }
  async status(config: ServerDefinition, barkEnabled: boolean) {
    this.sync(config, barkEnabled, false);
    const row = this.row()!;
    const pending = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbox").one().count > 0;
    await this.arm();
    return { id: row.id, name: row.name, status: row.status, lastSeen: row.last_seen, ipv4: row.ipv4, ipv6: row.ipv6,
      monitoredSince: row.monitored_since, timeoutSeconds: row.timeout_seconds, notificationPending: pending };
  }
  async disable(): Promise<void> {
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("UPDATE monitor SET disabled=1 WHERE singleton=1");
      this.ctx.storage.sql.exec("DELETE FROM outbox");
    });
    await this.ctx.storage.deleteAlarm();
  }
  async alarm(): Promise<void> {
    const row = this.row();
    if (!row || row.disabled) return;
    const snapshot = await this.env.CONTROL.getByName("control").snapshot(row.id);
    if (!snapshot.server) { await this.disable(); return; }
    if (this.row()?.disabled) return;
    this.sync(snapshot.server, !!snapshot.bark.url, false);
    await this.ctx.storage.setAlarm(Date.now() + 30_000);
    for (let i = 0; i < 10; i++) {
      if (this.row()?.disabled) break;
      const head = this.ctx.storage.sql.exec<EventRow>("SELECT * FROM outbox ORDER BY seq LIMIT 1").toArray()[0];
      if (!head || head.next_attempt > Date.now()) break;
      try {
        await sendBark(snapshot.bark, head.title, head.body);
        this.ctx.storage.sql.exec("DELETE FROM outbox WHERE seq=?", head.seq);
      } catch {
        const delay = Math.min(300_000, 30_000 * 2 ** Math.min(head.attempts, 4));
        this.ctx.storage.sql.exec("UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE seq=?", Date.now() + delay, head.seq);
        console.warn(JSON.stringify({ event: "bark_delivery_failed", serverId: row.id }));
        break;
      }
    }
    await this.arm();
  }
}
