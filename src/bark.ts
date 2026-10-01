import { barkUrl, type BarkSettings } from "./config";

// Never include Bark's device URL or its response body in logs/errors.
export async function sendBark(settings: BarkSettings, title: string, body: string): Promise<void> {
  const url = barkUrl(settings.url);
  if (!url) throw new Error("Bark 未配置");
  const response = await fetch(url.toString(), {
    method: "POST", redirect: "error", signal: AbortSignal.timeout(10_000),
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title, body, group: settings.group, level: "timeSensitive" })
  });
  if (!response.ok) { await response.body?.cancel(); throw new Error("Bark 请求失败"); }
  // Bark can return HTTP 200 with an application-level error. Limit the body.
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Bark 响应为空");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16_384) throw new Error("Bark 响应过大");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  let result: unknown;
  try { result = JSON.parse(new TextDecoder().decode(bytes)); } catch { throw new Error("Bark 响应格式错误"); }
  if (!result || typeof result !== "object" || !("code" in result) || result.code !== 200) throw new Error("Bark 未接受推送");
}
