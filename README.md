# Enoki

开箱即用的轻量 Linux 服务器监控平台，Rust 编写的探针本体仅 1M。

采取探针 POST Hub 架构，使用 [protobuf](https://github.com/protocolbuffers/protobuf) 作数据序列化协议以减少探针消耗的流量。

## 功能

Enoki **没有**以下功能：

- 依赖任何外部库的指标
- 多用户系统
- OAuth 验证
- Windows / Mac 等系统支持
- 国际化
- Hub 主动 Pull 探针
- GPU 监控
- S.M.A.R.T. 监控
- 阈值和通知
- Hub 向探针所在主机下发命令
- 通过 Docker 安装探针

Enoki **有**以下功能：

- 针对多种架构编译的探针
- 从 Hub 分发探针二进制文件从而不依赖探针侧额外网络连通性
- REST API
- 主页的卡片瀑布流 / 表格视图
- Hub 侧触发探针更新 / 自删除
- 探针常态下不拥有 root 权限
- CPU / RAM / 磁盘 / 网络接口等多种常见指标
- 可配置的采集和上报间隔
- 稳定和安全性
