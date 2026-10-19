<p align="right"><a href="README.md">English</a> · <b>简体中文</b></p>

# LoopCtrl-Server

[LoopCtrl](https://github.com/Souitou-iop/LoopCtrl) 的网络连接层：提供让操作员（Operator）从跨网络环境安全访问手机端 LoopCtrl 服务的服务端组件。本仓库包含的所有内容均可完全私有化自建部署。

LoopCtrl 在 iPhone 上运行长期驻留的 XCUITest runner，对外提供加密的 JSON-RPC API（协议 v1，默认端口 8300）。如果在同一 Wi-Fi 局域网内，操作员可直接直连；如果处于公网或跨网络环境，则需要一条通往手机的网络通路。本仓库提供两种可相互替换的方案：

| | App 内置中继 (`connect/relay/`) | Headscale 虚拟专网 (`connect/headscale/`) |
|---|---|---|
| **手机端配置** | 在 LoopCtrl 内直接扫码邀请二维码即可，零额外配置。 | 通过 Shadowrocket（或其他 Tailscale 兼容客户端）填入 pre-auth key 加入 tailnet。 |
| **服务端** | 单个轻量级 Python 进程，置于 HTTPS 反向代理后。 | Headscale + 内置 DERP 中继，HTTPS 代理，UDP 3478 STUN。 |
| **传输机制** | 经由中继的 HTTPS 长轮询（long-poll）。 | WireGuard；NAT 允许时点对点直连，否则经由自建 DERP 中转。 |
| **操作员连入** | 携带 Bearer token 访问 `relay/operator` 接口。 | 从具有 `tag:operator` 标签的节点直接访问 `100.64.x.y:8300`。 |
| **适用场景** | 默认首选。客户 iPhone 端无需繁琐网络配置。 | 备用方案，或适合团队自身已有 Tailnet 基础设施的场景。 |

无论采用哪种连接方式，操作员与手机之间均建立端到端配对（X25519），每次请求都使用 LoopCtrl v1 信封在端侧封装与加密。**无论是中继服务器还是 Headscale 节点，均无法解密或伪造请求内容。** 中继在设计上即为「非受信」中间人：邀请链接在生成时就已经由操作员指明了手机应当信任的操作员公钥。

## 目录结构

```
connect/relay/        中继服务器实现、自测套件、操作员工具、Dockerfile、
                      compose 配置、nginx 与 systemd 模板
connect/headscale/    Headscale + 内置 DERP：compose 文件、配置、ACL 策略、nginx
cli/                  `loopctrl` 操作员命令行工具（支持直连或通过中继连接）
docs/                 自建部署指南与协议架构规范
```

## 快速上手

使用 Docker 并在自己的 HTTPS 反向代理后部署中继：

```sh
cd connect/relay
cp relay.env.example relay.env && $EDITOR relay.env
install -d -m 0700 -o 10001 -g 10001 state
docker compose up -d
curl -s http://127.0.0.1:8787/healthz
```

生成邀请凭证并开始操作手机：

```sh
export LOOPCTRL_RELAY_URL=https://relay.example.com
export LOOPCTRL_RELAY_OPERATOR_TOKEN=...      # 来自 relay.env
cli/loopctrl relay enroll --name "Alex"       # 输出 loopctrl://connect 链接；可将其转为二维码展示
cli/loopctrl relay devices
cli/loopctrl relay pair --device-id dev_...   # 自动通过审批：邀请中已包含你的公钥
cli/loopctrl relay call --device-id dev_... device_info
```

完整指南：

- [docs/self-host-relay.md](docs/self-host-relay.md)：中继部署（Docker 或 systemd）。
- [docs/self-host-headscale.md](docs/self-host-headscale.md)：Headscale + DERP 部署，以及手机端通过 Shadowrocket 连入。
- [docs/protocol.md](docs/protocol.md)：各组件工作流及各层通信契约定义。

## 容器镜像

发布 Release 标签后会自动构建并发布 `ghcr.io/souitou-iop/loopctrl-relay:<version>`（以及 `:latest`）。Headscale 直接使用官方上游镜像 `headscale/headscale`。

## 开发与自测

```sh
python3 connect/relay/selftest.py     # 进程内完整模拟中继与两端交互；无需连接真机 iPhone
ruff check .
```

要求 Python 3.10+，仅依赖标准库（操作员 CLI 若环境中已安装 `cryptography` 则调用其进行 X25519 配对，否则回退到纯 Python 实现）。

## 许可证

Apache-2.0，与 LoopCtrl 保持一致。
