# Enoki

![GitHub License](https://img.shields.io/github/license/YKDZ/enoki)

安全且开箱即用的轻量 Linux 服务器监控平台。

Rust 编写的探针本体仅 `2.2 MiB`，单探针常态 PSS 约 `2 MiB`。

采取探针 POST Hub 架构，使用 [protobuf](https://github.com/protocolbuffers/protobuf) 作数据序列化协议以减少探针消耗的流量。

## 功能

Enoki **没有**以下功能：

- 多用户系统
- OAuth 验证
- Windows / Mac 等系统支持
- 国际化
- Hub 主动 Pull 探针
- GPU 监控
- 阈值和通知
- Hub 下发任意 Shell 命令
- 通过 Docker 安装探针

Enoki **有**以下功能：

- 针对多种架构编译的探针
- 从 Hub 分发探针二进制文件从而不依赖探针侧额外网络连通性
- REST API
- 主页的卡片瀑布流 / 表格视图
- Hub 侧触发探针更新 / 自删除
- 探针常态下不拥有 root 权限
- CPU / RAM / 磁盘 / 网络接口等多种常见指标
- 基于时钟的指标级采集 / 上报间隔
- 主机级可以开关的指标

> Enoki 有意保持这种简洁性，若你需要更多外部指标，可以自行二次开发。
>
> 我们的架构从探针到数据库到 Web UI 全链路都是易于在编译前扩展的；现有签名、资产分发和 Probe 本地边界可作为自定义分发链路的基础。

## 界面

### 卡片主机视图

![卡片主机视图](static/main-card.png)

### 表格主机视图

![表格主机视图](static/main-table.png)

### 主机详情页

![主机详情页](static/host.png)

## 安全性

Enoki 的安全边界尽量保持简单：

- 管理界面可查看主机信息并触发敏感操作，建议仅在可信网络中使用。
- 生产环境和 Docker 部署默认要求 `OWNER_PASSWORD`；`ENOKI_WEB_UI_NO_PASSWORD=true` 只适合完全可信的内网、演示或临时截图环境。生产或 Docker 环境必须同时显式设置 `ENOKI_ALLOW_INSECURE_NO_PASSWORD=true` 才能启用无密码模式。
- 探针接口可单独暴露给探针访问，公网部署时应使用 HTTPS 或可信隧道；传输加密依赖这一层完成。
- 探针注册后会生成自己的非对称身份密钥，后续上报和操作状态使用请求签名证明身份。签名会绑定 method、canonical origin、path、query、nonce、timestamp 和请求体 hash。
- Hub 位于 HTTPS 反代后时，只有在显式信任转发头后才会用 `X-Forwarded-Proto` / `X-Forwarded-Host` 计算 Probe 签名 origin；默认不信任这些 header。启用前必须确保公网客户端不能直达 Hub 伪造这些 header。
- 探针身份私钥和启动配置需要保持私密，配置文件不应允许其他用户读取。
- Hub 分发探针安装脚本和二进制资产；探针升级前会校验资产清单签名、受信公钥指纹、归档校验和、目标版本和本地防降级规则。
- 探针只会从最初安装时配置的 Hub 下载升级资产。安装器会把 canonical Hub URL 写入 root-owned install metadata，升级和卸载入口会在 token validation、资产下载和状态上报前校验 bootstrap Hub URL 与该 metadata 一致。
- 官方版使用本仓库配置的资产签名密钥和安装脚本签名密钥；如果不想信任我们的发布链，可以 fork 仓库、配置自己的发版密钥并自行发布 Hub 镜像和探针资产。
- Hub 管理员可以触发探针升级和卸载，因此 Hub 权限、Hub 数据目录、资产签名私钥和容器镜像发布权限都属于高信任边界。
- 探针常态下不以 root 运行；升级和卸载通过受限的 systemd 入口提权，只允许执行内置操作，不支持下发任意系统命令。

## 部署

部署分为 Hub 和探针两部分。Hub 推荐使用 Docker 部署；探针在 Web UI 中生成安装命令后，复制到目标 Linux 主机执行。

生产环境和 Docker 部署默认必须设置 `OWNER_PASSWORD`。开发环境如果未设置密码，Hub 会在启动日志中生成一个临时管理员密码；容器部署不会自动生成临时密码，除非显式启用无密码模式。

Hub 容器内默认监听两个端口：

- `3000`：Web UI 和管理 API
- `3001`：Probe API，供探针注册、上报、下载安装脚本和资产

### Docker Run

```sh
docker run -d \
  --name enoki-hub \
  --restart unless-stopped \
  -p 3000:3000 \
  -v /opt/enoki:/data \
  -e OWNER_PASSWORD='请替换为强密码' \
  -e ENOKI_PUBLIC_HUB_URL='https://example.com' \
  -e ENOKI_PUBLIC_HTTPS=true \
  ghcr.io/ykdz/enoki-hub:latest
```

如果需要只把 Probe API 暴露给公网或隧道，可以额外映射 `3001`：

```sh
docker run -d \
  --name enoki-hub \
  --restart unless-stopped \
  -p 3000:3000 \
  -p 3001:3001 \
  -v /opt/enoki:/data \
  -e OWNER_PASSWORD='请替换为强密码' \
  -e ENOKI_PUBLIC_HUB_URL='https://probe.example.com' \
  -e ENOKI_PUBLIC_HTTPS=true \
  ghcr.io/ykdz/enoki-hub:latest
```

### Docker Compose

```yaml
services:
  enoki-hub:
    image: ghcr.io/ykdz/enoki-hub:latest
    container_name: enoki-hub
    restart: unless-stopped
    ports:
      - "3000:3000"
      # 如果 Probe API 需要单独暴露，取消下一行注释。
      # - "3001:3001"
    volumes:
      - /opt/enoki:/data
    environment:
      OWNER_PASSWORD: 请替换为强密码
      ENOKI_PUBLIC_HUB_URL: https://example.com
      ENOKI_PUBLIC_HTTPS: "true"
```

### 环境变量

| 变量                                             | 默认值                                      | 说明                                                                                       |
| ------------------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `OWNER_PASSWORD`                                 | 无                                          | 管理员登录密码。Docker / 生产环境必填。                                                    |
| `ENOKI_WEB_UI_NO_PASSWORD`                       | `false`                                     | 开启后 Web UI 和管理 API 无需登录即可访问。仅适合完全可信的内网、演示或临时截图环境。      |
| `PORT`                                           | `3000`                                      | Web UI 和管理 API 监听端口。容器内通常不需要修改。                                         |
| `HOST`                                           | `0.0.0.0`                                   | Web UI 和管理 API 监听地址。                                                               |
| `ENOKI_PROBE_PORT`                               | `3001`                                      | Probe API 监听端口。容器内通常不需要修改。                                                 |
| `ENOKI_PROBE_HOST`                               | 同 `HOST`                                   | Probe API 监听地址。                                                                       |
| `ENOKI_DATA_ROOT`                                | `/data`                                     | Hub 数据目录。Docker 部署时应挂载持久化目录到这里。                                        |
| `ENOKI_SQLITE_PATH`                              | `/data/enoki.db`                            | SQLite 数据库文件路径。                                                                    |
| `ENOKI_PUBLIC_HUB_URL`                           | 自动使用当前访问地址                        | 生成探针安装命令时使用的 Hub 地址。跨公网、反代或隧道部署时建议显式设置。                  |
| `ENOKI_PUBLIC_HTTPS`                             | `false`                                     | 强制按 HTTPS 生成安全 Cookie。Hub 位于 HTTPS 反代后时建议设为 `true`。                     |
| `ENOKI_TRUST_PROXY_HEADERS`                      | `false`                                     | 登录 Cookie 判断请求是否为 HTTPS 时信任反代头。仅在可信反代后启用。                        |
| `ENOKI_TRUSTED_PROXY_HEADERS`                    | `false`                                     | Probe API 读取探针来源 IP 时信任转发头。仅在可信反代后启用。                               |
| `ENOKI_HOST_STATUS_STALE_AFTER_SECONDS`          | `30`                                        | 主机多久未上报后显示为上报延迟。                                                           |
| `ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS`        | `90`                                        | 主机多久未上报后显示为离线，必须大于上一个值。                                             |
| `ENOKI_METRICS_RETENTION_DAYS`                   | `7`                                         | 历史指标保留天数。                                                                         |
| `ENOKI_CLOCK_SKEW_THRESHOLD_SECONDS`             | `300`                                       | 探针时间与 Hub 时间偏移超过此值时记录时钟偏移。                                            |
| `ENOKI_PROBE_INSTALL_PATH`                       | `/usr/local/bin/enoki-probe`                | 生成探针安装命令时使用的默认安装路径。                                                     |
| `ENOKI_PROBE_ASSET_DIR`                          | `/app/probe-assets`                         | Hub 分发探针安装脚本和二进制资产的目录。                                                   |
| `ENOKI_INSTALL_SCRIPT_PATH`                      | `${ENOKI_PROBE_ASSET_DIR}/install-probe.sh` | 探针安装脚本路径。                                                                         |
| `ENOKI_PROBE_OPERATION_ACCEPTED_TIMEOUT_SECONDS` | `300`                                       | 探针操作已接收但未开始运行的超时时间。                                                     |
| `ENOKI_PROBE_OPERATION_RUNNING_TIMEOUT_SECONDS`  | `900`                                       | 探针操作运行中的超时时间。                                                                 |
| `ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET`     | 启动时随机生成                              | 探针升级 / 卸载操作 token 签名密钥。多实例或需要跨重启保留未完成操作时应设置为稳定随机值。 |
