import source from "../agent/agent.py";
import template from "../agent/install.sh";
import service from "../agent/server-probe.service";

function base64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
export function installationScript(origin: string, serverId: string, token: string): string {
  const config = JSON.stringify({ workerUrl: origin, serverId, token, intervalSeconds: 30, requestTimeoutSeconds: 10 });
  // Replace assignments only; the template's missing-payload guard keeps literal markers.
  return template.replace("CONFIG_B64='__CONFIG_BASE64__'", `CONFIG_B64='${base64(config)}'`)
    .replace("AGENT_B64='__AGENT_BASE64__'", `AGENT_B64='${base64(source)}'`)
    .replace("SERVICE_B64='__SERVICE_BASE64__'", `SERVICE_B64='${base64(service)}'`);
}
function shellQuote(value: string): string { return `'${value.replaceAll("'", "'\"'\"'")}'`; }
export function installationCommand(origin: string, ticket: string): string {
  return `curl -fsSL -X POST -H 'Content-Type: application/json' --data ${shellQuote(JSON.stringify({ ticket }))} ${shellQuote(`${origin}/api/install`)} | sudo bash`;
}
