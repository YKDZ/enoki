# Enoki

轻量的 Linux 服务器监控平台，Rust 编写的探针本体仅 1M。

采取探针 POST Hub 架构，使用 [protobuf](https://github.com/protocolbuffers/protobuf) 作数据序列化协议以减少探针消耗的流量。

Enoki 没有这些功能：

- 任何外部库
- 多用户系统
