# tcpscope · 了不起的 TCP

> A microscopic scope for TCP — watch a real kernel socket complete its 3-way handshake,
> send PSH+ACK payloads, and tear down, with RFC 9293 headers and checksums decoded live.

一个零外部依赖的 Go 单文件 TCP 可视化实验室。启动后自动在 `127.0.0.1:9527` 开启**真实操作系统内核 TCP 服务端**，并通过 `//go:embed` 把可视化前端打包进一个可执行文件，浏览器里看到的每一帧都对应真实的 Socket 行为。

## ✨ 特性

- **真实内核 Socket**：三次握手、PSH+ACK 载荷收发、四次挥手全部由 `net.Listen` / `net.DialTCP` 驱动，不是模拟动画。
- **RFC 9293 报文解剖**：按规范构造 20 字节 TCP 首部，实时计算伪首部反码求和校验和。
- **单文件分发**：`//go:embed` 内嵌 UI，编译后只需一个可执行文件。
- **零第三方依赖**：仅用 Go 标准库。
- **科技感可视化**：左右分栏 + 物理网线帧流动效果，报文序列、标志位、序号/确认号一目了然。

## 📁 目录结构

- `awesome_tcp.go`：Go 原生内核 TCP 服务端（`127.0.0.1:9527`）+ 客户端拨号器 + RFC 9293 报文解剖器，通过 `//go:embed awesome_tcp.html` 将前端打包进单个可执行文件。
- `awesome_tcp.html`：可视化控制台界面（可独立双击在浏览器预览，也可被 Go 编译内嵌后驱动真实系统 Socket）。
- `go.mod`：零第三方依赖的模块定义。
- `build.bat` / `build.sh`：Windows / macOS / Linux 一键编译并启动脚本。

## 🚀 快速开始

需要 Go 1.21+。

### Windows

双击 `build.bat`，或：

```powershell
go build -ldflags="-s -w" -o awesome_tcp.exe .
.\awesome_tcp.exe
```

### macOS / Linux

```bash
chmod +x build.sh && ./build.sh
```

启动后程序会自动监听 `127.0.0.1:9527`，并打开浏览器访问 `http://127.0.0.1:19527` 控制台。右上角徽章显示 **「🟢 Go 原生内核 Socket 引擎已挂载 (:9527)」** 即表示已连接真实内核引擎。

## 🔌 HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/status` | 引擎状态探针 |
| GET | `/api/connect` | 发起真实 TCP 三次握手并自动发送 `hello` |
| POST | `/api/client-send` | 客户端向真实 Socket 发送载荷 `{"message":"..."}` |
| POST | `/api/server-send` | 服务端主动推送载荷 |
| GET | `/api/disconnect` | 断开真实连接（触发四次挥手） |
| GET | `/api/packets` | 获取捕获的完整报文序列 |

## 📄 License

[MIT](LICENSE) © 2026 Tomiaocat
