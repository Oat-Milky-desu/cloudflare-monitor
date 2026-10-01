# Cloudflare Workers 服务器探针

这个项目通过 Cloudflare Worker 和 Durable Objects 监控 Linux 服务器。每台服务器运行一个 Python 3 客户端，每 30 秒向 Worker 发送心跳。控制台可创建和管理客户端、查看最近状态与公网出口 IP，并设置 Bark 离线和恢复通知。

<!-- deploy-button:start -->
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https%3A%2F%2Fgithub.com%2FOat-Milky-desu%2Fcloudflare-monitor)
<!-- deploy-button:end -->

## 一键部署

点击上面的按钮，即可将本仓库部署到自己的 Cloudflare 账户。Cloudflare 会读取 Wrangler 配置、创建并绑定项目所需的 Durable Objects，再构建和部署 Worker。部署页面会要求为 `ADMIN_PASSWORD` 提供机密值。

`ADMIN_USERNAME` 默认是 `admin`，在 `wrangler.jsonc` 中配置。请为部署设置一个自己保管的 `ADMIN_PASSWORD`，长度为 12–128 个字符。仓库中的 `.dev.vars.example` 和 [secrets.example.json](secrets.example.json) 仅展示字段格式，密码留空，服务在配置有效密码前不允许登录。真实本地密码只放在被 Git 忽略的 `.dev.vars` 中；生产密码在 Cloudflare 部署表单中另行设置。

部署完成后，打开 Worker 地址并用配置的用户名和密码登录。密码以迭代 100,000 次的 PBKDF2 派生值保存。连续登录失败 5 次后，接下来的 5 分钟内会限制登录尝试。登录会话由有效期 12 小时、设置了 `HttpOnly` 和 `SameSite=Strict` 的 Cookie 维护，并由 CSRF 校验保护；退出登录会使当前会话失效。忘记密码时，在 Cloudflare Worker 的机密设置中更新 `ADMIN_PASSWORD` 并重新部署，这也会使已有会话失效。

## 手动部署

需要 Node.js 22.12 或更新版本和 Corepack。下载代码后安装依赖并完成本地检查：

```sh
cp .dev.vars.example .dev.vars
# 在 .dev.vars 中设置本地测试密码，勿使用生产密码
corepack pnpm install --frozen-lockfile
corepack pnpm run types
corepack pnpm run typecheck
corepack pnpm test
corepack pnpm run dry-run
```

登录 Cloudflare，并在交互提示中设置生产密码。不要把真实密码写在命令参数、配置文件或仓库中：

```sh
corepack pnpm exec wrangler login
corepack pnpm exec wrangler secret put ADMIN_PASSWORD
corepack pnpm run deploy
```

按需修改 `wrangler.jsonc` 中的 `ADMIN_USERNAME`，默认值为 `admin`。本地开发时复制 `.dev.vars.example` 为 `.dev.vars`，将示例密码替换成自己的本地密码，再运行 `corepack pnpm run dev`。`.dev.vars` 已加入忽略规则，不要提交它。

## 管理控制台

登录后可在控制台创建客户端。为客户端填写名称和离线超时时间，控制台会生成一条单次使用的安装命令，有效期为 10 分钟。重新生成命令会使之前未使用的票据失效，但不会立即影响现有探针。只有在服务器取得新的安装脚本时，客户端令牌才会轮换，旧安装随即停止上报。请在目标 Linux 服务器上尽快运行，并把命令当作机密处理。

安装命令会安装 Python 探针、写入客户端配置并创建 systemd 服务。目标机需要正在运行的 systemd、`curl`、`bash` 和 `sudo` 权限；也可以用 root 账户执行。客户端要求 Python 3.7 或更新版本；若未安装 Python 3，安装器会尝试使用 apt、dnf、yum 或 zypper 安装，并检查版本。安装后服务每 30 秒发送一次心跳，并每 5 分钟查询 Worker 的 `/api/ip`，把可检测到的 IPv4 和 IPv6 出口地址上报给控制台。若目标网络没有某个 IP 地址族，控制台会显示“未报告”；显示的是客户端访问 Worker 时的公网出口地址。

探针只能报告客户端是否能联系 Worker，不能检查服务器上的网站、进程或端口。断电、客户端退出、主机网络中断以及 Worker 暂时不可达都会表现为心跳超时。Cloudflare 的调度不是实时保证，离线状态和通知可能晚于设定的超时时间。

每个客户端的监控状态由独立 Durable Object 保存，控制台配置保存在项目控制 Durable Object 中。Cloudflare 会按 Wrangler 配置为部署创建这些资源。

## Bark 通知

在控制台的 Bark 设置中填写完整 HTTPS 设备推送地址（例如 `https://api.day.app/你的设备密钥`）及可选分组，保存后发送测试通知。已保存地址只回显服务域名，输入框留空会保留原值；勾选清除地址可以停用通知。超时前的首次心跳会将客户端标记为在线而不推送；超时会触发离线通知，离线后恢复心跳会触发恢复通知。网络故障和重试可能导致重复推送。

## 从旧版升级

旧版的 `ADMIN_TOKEN`、`SERVER_CONFIG` 和 `BARK_URL` 不会自动导入新版控制台。升级后请用新的 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 登录，在控制台重新创建客户端，并重新填写 Bark 设置。可以从旧配置中复制名称和超时等信息；每个客户端会在控制台生成新的安装命令。

## 项目结构

- `src/`：Cloudflare Worker、控制台 API 与 Durable Objects。
- `public/`：控制台页面。
- `agent/`：Python Linux 探针和 systemd 服务文件。
- `scripts/set-deploy-button.mjs`：验证公开仓库并写入 Cloudflare 部署按钮。

## 相关配置

`ADMIN_PASSWORD` 是必需的 Worker secret，长度需为 12–128 个字符。用户名默认由 `wrangler.jsonc` 中的 `ADMIN_USERNAME` 设置。部署按钮的设置方式和 `.dev.vars.example` secret 提示格式见 [Cloudflare Deploy to Cloudflare 文档](https://developers.cloudflare.com/workers/platform/deploy-buttons/)。
