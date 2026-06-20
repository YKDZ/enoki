# Enoki

Enoki MVP 的生产部署路径是将 Hub 作为 Docker 容器运行。Probe 不通过
Docker 部署；每台 Managed Host 上的 Probe 应直接安装为宿主机
`systemd` 服务，这样它才能按宿主机视角采集系统状态，而不是受容器环境限制。

## Hub Docker 部署

### 构建镜像

在仓库根目录执行：

```sh
DOCKER_BUILDKIT=1 docker build -f apps/hub/Dockerfile -t enoki-hub:local .
```

Dockerfile 依赖 BuildKit 的 cache mount 来缓存 pnpm store。构建流程采用
Turborepo 的 Docker prune 策略：先为 `@enoki/hub` 和 `@enoki/web` 裁剪
monorepo，基于裁剪后的 lockfile 和 package metadata 安装依赖，再复制裁剪后的
源码完成 Hub 与 Web UI 构建。最终运行镜像包含 Node.js Hub、数据库迁移文件和已
构建的 Web UI 静态资源。

镜像默认声明持久化目录 `/data`，默认监听 `3000` 端口。

### 使用 docker run

```sh
mkdir -p /var/lib/enoki

docker run -d \
  --name enoki-hub \
  --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  -v /var/lib/enoki:/data \
  -e OWNER_PASSWORD='replace-with-a-long-random-password' \
  -e ENOKI_PUBLIC_HTTPS=true \
  -e ENOKI_TRUST_PROXY_HEADERS=true \
  -e ENOKI_TRUSTED_PROXY_HEADERS=true \
  -e ENOKI_METRICS_RETENTION_DAYS=7 \
  enoki-hub:local
```

`/data` 是 Hub 的数据根目录，必须挂载到持久化存储。默认 SQLite 数据库路径是
`/data/enoki.db`。只有在同时挂载了包含目标数据库文件的持久化路径时，才建议用
`ENOKI_SQLITE_PATH` 覆盖默认路径。

示例将容器端口只发布到 `127.0.0.1:3000`，适合放在本机反向代理之后运行。

### 使用 docker compose

```yaml
services:
  hub:
    image: enoki-hub:local
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - enoki-data:/data
    environment:
      OWNER_PASSWORD: ${OWNER_PASSWORD:?set OWNER_PASSWORD}
      ENOKI_PUBLIC_HTTPS: "true"
      ENOKI_TRUST_PROXY_HEADERS: "true"
      ENOKI_TRUSTED_PROXY_HEADERS: "true"
      ENOKI_METRICS_RETENTION_DAYS: "7"

volumes:
  enoki-data:
```

启动 Compose 前，在 shell 或 `.env` 中设置 `OWNER_PASSWORD`。

## 运行配置

`OWNER_PASSWORD` 是 Docker 和 production 模式的必填项。Hub 从部署环境读取
Owner 密码，不会把它写入 SQLite；如果 Docker/production 环境缺少该变量，Hub
会拒绝启动。

Owner session 使用 HTTP-only、SameSite=Lax cookie。当前 MVP 把 session ID 保
存在 Hub 进程内存中，不读取单独的 `SESSION_SECRET` 环境变量；容器重启会使现有
Owner 浏览器会话失效。当 Hub 看到 HTTPS、设置了 `ENOKI_PUBLIC_HTTPS=true`，
或在 `ENOKI_TRUST_PROXY_HEADERS=true` 且可信反向代理发送
`X-Forwarded-Proto: https` 时，session cookie 会被标记为 Secure。

Docker 镜像默认设置 `HOST=0.0.0.0`、`PORT=3000`。如需改端口，需要同时调整
容器内 `PORT` 和 Docker 的端口发布规则。

`ENOKI_METRICS_RETENTION_DAYS` 控制 metrics 保留天数，默认值是 `7`，必须是正
整数。

可信代理相关配置分为两类：

- `ENOKI_TRUST_PROXY_HEADERS=true` 或 `1`：Owner 认证会信任
  `X-Forwarded-Proto`，用于判断 Secure session cookie。
- `ENOKI_TRUSTED_PROXY_HEADERS=true`：Probe 接口会信任转发头，用于推导
  Observed IP。

只有当 Hub 只能通过反向代理访问，并且该反向代理会剥离客户端伪造的转发头、再写
入自己的转发头时，才应启用可信代理头。

## HTTPS 与反向代理

公网 Hub 流量应由 nginx、Caddy、Traefik 等反向代理终止 HTTPS。Hub 可以在反向
代理后继续以普通 HTTP 运行；Hub 本身不要求绑定 `443`，也不强制使用 `443` 端口。

常见拓扑是：

```text
Internet HTTPS :443 -> reverse proxy -> http://127.0.0.1:3000
```

启用 `ENOKI_TRUST_PROXY_HEADERS` 时，反向代理需要向 Hub 传递正确的原始协议头，
例如 `X-Forwarded-Proto: https`。

## 日志

Hub 将应用日志写入 stdout 和 stderr。日志收集与轮转应交给容器运行时或宿主机日
志系统，例如：

```sh
docker logs -f enoki-hub
```

Hub 不会把应用日志文件写入 `/data`；SQLite 中保存的是 Hub 业务状态和最小审计日
志。

## 本地 Docker smoke 检查

在仓库根目录执行：

```sh
pnpm docker:smoke
```

该脚本会构建 Hub 镜像，验证缺少 `OWNER_PASSWORD` 时启动失败，使用挂载的
`/data` 启动容器，等待 health endpoint，检查 `/data/enoki.db` 中的迁移结果，
验证 Owner 登录接口可用，并确认 `index.html` 引用的 Web UI 构建产物可以从容器
中正常访问。脚本默认为 Docker 构建启用 BuildKit。

## MVP 端到端 smoke 检查

在 devcontainer 或本地开发环境中执行：

```sh
pnpm smoke:mvp
```

该脚本会构建 Web UI、Hub 和 Probe binary，启动一个临时 Hub，再使用真实
`target/debug/enoki-probe` 完成注册和运行。脚本验证 Owner 登录、未登录禁止访问
Managed Host 状态，并在已有 Managed Host 与 Metrics 后再次验证未登录请求仍无法
读取业务状态。脚本还验证 Enrollment Token 与安装命令生成、Managed Host 出现在
Web UI、overview card 显示真实 Metrics、详情页渲染历史图表与实时尾部相关 DOM、
hostname-derived Display Name、Inventory 网络数据、WebSocket overview/detail 更
新、Owner 通过 Web UI 编辑 Probe Configuration、运行中 Probe 无需重启即可拉取并
应用该配置，以及 soft delete 后旧 Probe Identity 的 report 被拒绝。

`pnpm smoke:mvp` 使用 Playwright 驱动已构建 Web UI。首次在新环境运行前，如果尚
未安装 Chromium 浏览器缓存，请执行：

```sh
pnpm exec playwright install chromium
```

如果系统依赖缺失，可改用：

```sh
pnpm exec playwright install --with-deps chromium
```

也可以通过 `ENOKI_SMOKE_BROWSER_EXECUTABLE=/path/to/chrome` 指向已有浏览器。只
有在明确需要保留非浏览器 smoke 路径时，才应设置
`ENOKI_SMOKE_SKIP_BROWSER=1 pnpm smoke:mvp`；该模式会跳过 DOM 断言，但仍会保留
Hub、Probe、Web API、WebSocket、Probe Configuration sync 和 soft delete 验证。

如果已经完成构建，可以跳过脚本内构建：

```sh
ENOKI_SMOKE_SKIP_BUILD=1 pnpm smoke:mvp
```

真实 Linux host 的 systemd 安装验证仍应使用宿主机二进制服务路径，不要把 Probe
放进 Docker。可选验证步骤：

```sh
pnpm --filter @enoki/web build
pnpm --filter @enoki/hub build
cargo build -p enoki-probe --release
pnpm smoke:mvp
```

随后在 Web UI 中创建 Enrollment Token，复制“添加主机”安装命令，在目标 Linux
主机上用 root 或 sudo 执行。若测试环境提供了 `192.168.2.22`，可以先进入该主机：

```sh
ssh 192.168.2.22
```

安装完成后检查：

```sh
sudo systemctl status enoki-probe
sudo journalctl -u enoki-probe -f
```

Hub 的 Managed Hosts 页面应出现该主机，详情页应持续更新 Inventory、Metrics 和
实时尾部数据。

## CI 与发布

GitHub Actions 分为三个 workflow：

- `CI`：在 Pull Request、`main` push 和手动触发时运行。它分阶段执行 Node 系
  format、lint、typecheck、test、protobuf 生成检查，Rust 系 `fmt`、`clippy`、
  `test`，并验证 Hub/Web 构建、Probe release 构建和 Hub Docker 镜像构建。
- `Release Hub`：在推送 `hub-v*` tag 或手动输入版本号时运行。它执行 Node 系
  检查、构建和测试，然后构建 Hub Docker 镜像并推送到 GHCR。
- `Release Probe`：在推送 `probe-v*` tag 或手动输入版本号时运行。它执行
  protobuf 和 Rust 检查，然后构建 Probe 二进制包并发布到 GitHub Release。
  `probe-v*` 只是发布触发 tag；下载地址和安装命令仍使用普通 `v*` 版本。

Probe 发布产物命名为：

```text
enoki-probe-x86_64-unknown-linux-gnu.tar.gz
enoki-probe-x86_64-unknown-linux-gnu.tar.gz.sha256
enoki-probe-aarch64-unknown-linux-gnu.tar.gz
enoki-probe-aarch64-unknown-linux-gnu.tar.gz.sha256
install-probe.sh
```

Hub 镜像发布到：

```text
ghcr.io/<github-owner>/enoki-hub:<version>
ghcr.io/<github-owner>/enoki-hub:latest
```

例如发版：

```sh
git tag hub-v0.1.0
git push origin hub-v0.1.0

git tag probe-v0.1.0
git push origin probe-v0.1.0
```

Turborepo 继续用于 monorepo 内部的 JS/TS build、test、typecheck 调度；GitHub
Release、Probe 多架构二进制、GHCR 登录和 Docker push 由 Actions job 编排，因
为这些步骤依赖 GitHub 权限、runner 架构矩阵和发布环境。
