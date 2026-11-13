# tcpscope · 了不起的 TCP

> A real protocol-stack lab: a browser TCP teaching simulation plus a live **TLS / HTTP / WebSocket** demo plane.

tcpscope 是一个零第三方依赖的 Go 单二进制协议实验室。它包含两个相互独立的区域：

- **TCP 教学模拟**：浏览器内的三次握手 / 序号演进 / 四次挥手动画与 TCP 报文解剖，保留原有的教学体验。
- **协议实验室**：真实的 `net/http` + 自研 RFC 6455 WebSocket + 动态 TLS。TLS 开关会真实重绑 `127.0.0.1:9527` 演示监听器，开启后 HTTP 变成 HTTPS、WS 变成 WSS。

## ✨ 特性

- **真实动态 TLS**：不是界面装饰。切换时关闭旧监听器/连接，重新绑定为 `tls.Listener`（或恢复明文），失败自动回滚。TLS 1.2+，强制 HTTP/1.1 ALPN 以保证 WS Upgrade 可用。
- **真实 HTTP/1.1 与 WebSocket**：演示面提供 HTTP 路由和 `/demo/ws` Upgrade；WS 帧编解码、mask、分片、ping/pong/close 全部只用标准库实现。
- **明文揭示开关**：TLS 开启后，报文/消息视图默认只显示加密形态；打开「显示解密明文」后才展示**应用端自己持有的明文**（HTTP/WS 载荷）。这不是密码学破解，而是「线上视角 vs 端点视角」的对照教学。服务端也通过 `reveal=1` 做闸门，不只是 CSS 隐藏。
- **多会话 + 会话列表**：每个 HTTP 请求 / WS 连接独立 Session，含协议、传输、计数、有界事件/帧缓存；支持上限、空闲清理、手动关闭。
- **TCP 帧重建**：由真实 HTTP/WS 字节流重建 TCP 首段与 PSH+ACK 段，复用 RFC 9293 首部/校验和逻辑，并在 UI 中标注「reconstructed」。
- **单二进制 · 零第三方依赖**：`//go:embed` 内嵌 UI；仅用 Go 标准库；Go 1.21+。
- **明亮实验室风**：保留浅色主题、加宽网线、速度滑块、LED/脉冲/光环等轻量动效。

## 📁 目录结构

| 文件 | 职责 |
| --- | --- |
| `awesome_tcp.go` | 进程入口（`main`）+ 旧 TCP 教学引擎（`-demo-mode=legacy`） |
| `config.go` | 命令行参数与默认值 |
| `lab.go` | 控制面/演示面生命周期、动态 TLS 切换、TLS 记录录制 |
| `lab_http.go` | 演示 HTTP 路由、内部 HTTP 客户端、请求/响应录制 |
| `lab_ws.go` | 演示 WebSocket 服务端与内部 WS 客户端 |
| `lab_control.go` | 控制面 REST 与 `/api/ws` 事件流 |
| `certs.go` | 自签名 ECDSA P-256 证书生成/加载/持久化 |
| `sessions.go` | 会话注册表、事件总线、TCP 帧模型 |
| `ws.go` | RFC 6455 握手与帧编解码（仅标准库） |
| `awesome_tcp.html` | 单文件前端：TCP 教学区 + 协议实验室 |
| `build.bat` / `build.sh` | Windows / macOS / Linux 一键编译并启动 |

## 🚀 快速开始

需要 Go 1.21+。

```bash
go build -ldflags="-s -w" -o awesome_tcp .
./awesome_tcp
```

Windows 也可以双击 `build.bat`。

启动后：

- 控制台：`http://127.0.0.1:19527`（明文控制面，浏览器不需要信任证书）
- 演示面：`http://127.0.0.1:9527`（默认明文；UI 打开 TLS 后变成 `https://`）

### 常用参数

```text
-control 127.0.0.1:19527   控制面地址
-demo    127.0.0.1:9527    演示面地址
-mode    stack|legacy      默认 stack；legacy 是旧的单连接裸 TCP 教学引擎
-tls                       启动时就开启 TLS（默认关闭）
-cert / -key               使用已有证书/私钥（否则自动生成）
-data-dir                  证书目录，默认 %AppData%\tcpscope（Unix: ~/.config/tcpscope）
-max-sessions              会话上限，默认 64
-open=false                不自动打开浏览器
```

## 🔐 TLS 与证书

- 首次启动自动生成 **ECDSA P-256 自签名证书**，SAN 包含 `127.0.0.1`、`::1`、`localhost`，有效期 1 年，私钥权限 `0600`。
- 证书/私钥保存在用户配置目录，**不会提交到仓库**；已加入 `.gitignore`。
- 控制面始终明文；**只有演示面** `9527` 受 TLS 开关影响。
- 切换 TLS 会断开现有演示连接，这是真实 TLS 的必然结果；UI 会明确提示。
- 外部验证：

```bash
curl http://127.0.0.1:9527/demo/hello
curl -k https://127.0.0.1:9527/demo/hello
wscat -c ws://127.0.0.1:9527/demo/ws
wscat -c wss://127.0.0.1:9527/demo/ws   # 自签证书需客户端跳过校验
```

## 👁 明文揭示

- TLS 开启且「显示解密明文」关闭：TLS 记录/HTTP/WS 视图只显示加密元数据、密文长度和加密占位；`/api/events?reveal=0` 与 `/api/ws?reveal=0` 不返回明文。
- 打开开关：重新订阅 `reveal=1`，展示应用端已经持有的明文，并标注「端点解密明文 · 不在网线上」。
- 关闭开关：不仅隐藏文本，还会清除已渲染的明文 DOM；恢复 `reveal=0` 事件流。
- TLS 关闭时开关禁用，明文直接展示。

## 🔌 控制面 API（19527）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/status` | 引擎、演示面、TLS、证书、会话数 |
| POST | `/api/tls` | `{"enabled":bool}`，真实切换 TLS；切换中返回 409 |
| GET | `/api/sessions` | 会话列表 |
| GET | `/api/sessions/{id}?reveal=1` | 会话详情 + 事件/帧（`reveal` 控制明文） |
| DELETE | `/api/sessions/{id}` | 关闭会话 |
| POST | `/api/demo/http` | 后端真实发起 HTTP 请求 `{method,path,headers,body,reveal}` |
| POST | `/api/demo/ws/open` | 打开真实 WS 客户端连接 |
| POST | `/api/demo/ws/send` | `{sessionId,type,data}` |
| POST | `/api/demo/ws/close` | `{sessionId}` |
| GET | `/api/events?since=&limit=&reveal=` | 事件轮询回退 |
| GET | `/api/ws?since=&reveal=` | 控制面 WebSocket 事件流 |
| GET | `/api/cert` | 下载自签名证书 PEM |

## 🧪 演示面路由（9527）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/demo/hello` | JSON 问候与请求计数 |
| POST | `/demo/echo` | 回显请求体（上限 64KB） |
| GET | `/demo/info` | 请求头、远端地址、协议、TLS 状态 |
| GET | `/demo/delay?ms=200` | 延迟演示（上限 5s） |
| GET | `/demo/ws` | WebSocket Upgrade |

## 🧪 测试

```bash
go test ./...
```

测试覆盖证书 SAN/持久化、WS 帧往返（文本/二进制/126 长度）、事件明文闸门、会话上限、TLS 开关与 HTTP 往返、控制面明文闸门。

> `-race` 需要 CGO 与 C 编译器；当前 Windows 环境未安装 gcc，因此请在有 C 工具链的环境运行 `CGO_ENABLED=1 go test -race ./...`。

## 🔒 安全模型

- 所有监听器只绑定 loopback；不对外网暴露。
- 控制面固定明文，便于浏览器零证书摩擦；演示面才受 TLS 开关控制。
- WS Upgrade 校验 `Origin`，拒绝非本机控制台来源；非浏览器客户端（无 Origin）放行。
- `reveal=0` 时服务端不返回应用层明文；不只是前端隐藏。
- 不记录明文到日志；生成的私钥不提交。
- 无第三方依赖；HTTP/WS/TLS 全部使用标准库。

## 📄 License

[MIT](LICENSE) © 2026 Tomiaocat
