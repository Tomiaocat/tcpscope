// ============================================================================
// 《了不起的TCP》(Awesome TCP) — 零依赖 Go 原生内核 Socket + //go:embed 单文件构建版
// ============================================================================
// 编译方式（将 awesome_tcp.html 与 awesome_tcp.go 放在同一目录）：
//   Windows:  go build -ldflags="-s -w" -o awesome_tcp.exe .
//   macOS:    go build -ldflags="-s -w" -o awesome_tcp .
//   Linux:    go build -ldflags="-s -w" -o awesome_tcp .
//
// 核心工作原理：
// 1. 使用 Go 1.16+ 标准库 //go:embed 将 awesome_tcp.html 完整编译进单个可执行文件
// 2. 启动时自动在 127.0.0.1:9527 开启操作系统内核级 TCP 服务端 (net.Listen("tcp"))
// 3. 当你在界面点击「连接服务端」、发送数据或主动推送时，同步驱动真实内核 TCP Socket
//    完成三次握手、PSH+ACK 载荷收发与四次挥手，并按照 RFC 9293 规范计算 20 字节首部与校验和
// ============================================================================

package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed awesome_tcp.html
var embeddedUI []byte

// TCPFlags 表示 TCP 首部第 13 字节的 6 个核心控制标志位
type TCPFlags struct {
	URG bool `json:"URG"`
	ACK bool `json:"ACK"`
	PSH bool `json:"PSH"`
	RST bool `json:"RST"`
	SYN bool `json:"SYN"`
	FIN bool `json:"FIN"`
}

// PacketRecord 表示一条被解剖的 TCP 报文帧完整记录
type PacketRecord struct {
	ID          uint64   `json:"id"`
	Timestamp   string   `json:"timestamp"`
	Direction   string   `json:"direction"` // "C2S" or "S2C"
	SrcPort     uint16   `json:"srcPort"`
	DstPort     uint16   `json:"dstPort"`
	Flags       TCPFlags `json:"flags"`
	RelSeq      uint32   `json:"relSeq"`
	RelAck      uint32   `json:"relAck"`
	RawSeq      uint32   `json:"rawSeq"`
	RawAck      uint32   `json:"rawAck"`
	WindowSize  uint16   `json:"windowSize"`
	Checksum    string   `json:"checksum"`
	PayloadLen  int      `json:"payloadLen"`
	PayloadText string   `json:"payloadText"`
	RawHex      string   `json:"rawHex"`
	Note        string   `json:"note"`
}

// AwesomeTCPEngine 管理本地真实 TCP 服务端、客户端 Socket 及报文解剖历史
type AwesomeTCPEngine struct {
	mu             sync.Mutex
	listener       net.Listener
	clientConn     *net.TCPConn
	serverSideConn *net.TCPConn
	serverPort     uint16
	clientPort     uint16

	clientISN uint32
	serverISN uint32
	clientSeq uint32
	serverSeq uint32

	hitCounter uint64
	pktID      uint64
	packets    []PacketRecord
}

func NewAwesomeTCPEngine() *AwesomeTCPEngine {
	return &AwesomeTCPEngine{
		serverPort: 9527,
		clientISN:  1842901000,
		serverISN:  3910452000,
		packets:    make([]PacketRecord, 0, 128),
	}
}

// StartRealTCPServer 自动启动本地真实 TCP 监听 (127.0.0.1:9527)
func (e *AwesomeTCPEngine) StartRealTCPServer() error {
	addr := fmt.Sprintf("127.0.0.1:%d", e.serverPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	e.listener = ln
	log.Printf("[了不起的TCP] 真实内核 TCP 服务端已自动启动并监听 %s (LISTEN)", addr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
				e.mu.Lock()
				e.serverSideConn = tcpConn
				e.mu.Unlock()
				go e.handleServerConn(tcpConn)
			}
		}
	}()
	return nil
}

// handleServerConn 服务端循环读取客户端真实字节流，并自动回复被请求次数 (1, 2, 3...)
func (e *AwesomeTCPEngine) handleServerConn(conn *net.TCPConn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[TCP Server] 连接读取结束: %v", err)
			}
			return
		}
		payload := string(buf[:n])
		hit := atomic.AddUint64(&e.hitCounter, 1)

		// 服务端向真实 Socket 回写当前被请求次数数字
		replyStr := fmt.Sprintf("%d", hit)
		_, _ = conn.Write([]byte(replyStr))
		log.Printf("[TCP Server :9527] 收到客户端 %d 字节 %q -> 自动回执第 %d 次响应 %q", n, payload, hit, replyStr)

		e.mu.Lock()
		e.recordFrameLocked("S2C", e.serverPort, e.clientPort, TCPFlags{PSH: true, ACK: true},
			e.serverSeq, e.clientSeq, []byte(replyStr),
			fmt.Sprintf("服务端收到 %q 后自动回复第 %d 次响应数字 %q", payload, hit, replyStr))
		e.serverSeq += uint32(len(replyStr))

		e.recordFrameLocked("C2S", e.clientPort, e.serverPort, TCPFlags{ACK: true},
			e.clientSeq, e.serverSeq, nil,
			fmt.Sprintf("客户端内核确认收到服务端响应 %q (Ack=%d)", replyStr, e.serverSeq))
		e.mu.Unlock()
	}
}

// ConnectAndSendDefaultHello 客户端真实拨号连接服务端，并默认发送 "hello"
func (e *AwesomeTCPEngine) ConnectAndSendDefaultHello() error {
	e.mu.Lock()
	if e.clientConn != nil {
		_ = e.clientConn.Close()
		e.clientConn = nil
	}
	e.clientSeq = 0
	e.serverSeq = 0
	e.mu.Unlock()

	raddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", e.serverPort))
	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return err
	}
	_ = conn.SetNoDelay(true)

	// 启动客户端异步读取协程，消费服务端发来的真实 Socket 字节流
	go func(c *net.TCPConn) {
		discardBuf := make([]byte, 4096)
		for {
			_, err := c.Read(discardBuf)
			if err != nil {
				return
			}
		}
	}(conn)

	laddr := conn.LocalAddr().(*net.TCPAddr)
	e.mu.Lock()
	e.clientConn = conn
	e.clientPort = uint16(laddr.Port)

	// 记录内核完成的 3 次握手帧 (SYN -> SYN+ACK -> ACK)
	e.recordFrameLocked("C2S", e.clientPort, e.serverPort, TCPFlags{SYN: true},
		0, 0, nil, "第一次握手 (SYN): 客户端同步初始序列号 ISN，消耗 1 个逻辑序号")
	e.clientSeq = 1

	e.recordFrameLocked("S2C", e.serverPort, e.clientPort, TCPFlags{SYN: true, ACK: true},
		0, e.clientSeq, nil, "第二次握手 (SYN+ACK): 服务端确认客户端 ISN 并同步自身序号")
	e.serverSeq = 1

	e.recordFrameLocked("C2S", e.clientPort, e.serverPort, TCPFlags{ACK: true},
		e.clientSeq, e.serverSeq, nil, "第三次握手 (ACK): 握手完成，状态进入 ESTABLISHED，物理网线激活!")
	e.mu.Unlock()

	log.Printf("[TCP Client :%d] 已完成与 127.0.0.1:%d 的三次握手，默认发送 \"hello\"", e.clientPort, e.serverPort)
	return e.ClientSend("hello", true)
}

// ClientSend 客户端向真实 TCP Socket 写入数据
func (e *AwesomeTCPEngine) ClientSend(msg string, isAuto bool) error {
	e.mu.Lock()
	conn := e.clientConn
	if conn == nil {
		e.mu.Unlock()
		return fmt.Errorf("客户端尚未连接")
	}
	rawPayload := []byte(msg)
	note := fmt.Sprintf("客户端发送载荷 %q (%d Bytes)", msg, len(rawPayload))
	if isAuto {
		note = "[连接后自动发送] " + note
	}
	e.recordFrameLocked("C2S", e.clientPort, e.serverPort, TCPFlags{PSH: true, ACK: true},
		e.clientSeq, e.serverSeq, rawPayload, note)
	e.clientSeq += uint32(len(rawPayload))
	e.mu.Unlock()

	_, err := conn.Write(rawPayload)
	return err
}

// ServerSend 服务端主动向客户端真实 Socket 推送数据
func (e *AwesomeTCPEngine) ServerSend(msg string) error {
	e.mu.Lock()
	conn := e.serverSideConn
	if conn == nil {
		e.mu.Unlock()
		return fmt.Errorf("尚无已连接的客户端")
	}
	rawPayload := []byte(msg)
	e.recordFrameLocked("S2C", e.serverPort, e.clientPort, TCPFlags{PSH: true, ACK: true},
		e.serverSeq, e.clientSeq, rawPayload,
		fmt.Sprintf("服务端主动推送 %q (%d Bytes)", msg, len(rawPayload)))
	e.serverSeq += uint32(len(rawPayload))

	e.recordFrameLocked("C2S", e.clientPort, e.serverPort, TCPFlags{ACK: true},
		e.clientSeq, e.serverSeq, nil,
		fmt.Sprintf("客户端确认收到服务端主动推送 (Ack=%d)", e.serverSeq))
	e.mu.Unlock()

	log.Printf("[TCP Server :9527] 主动向客户端推送 %d 字节: %q", len(rawPayload), msg)
	_, err := conn.Write(rawPayload)
	return err
}

// Disconnect 关闭真实客户端 TCP 连接（触发内核四次挥手）
func (e *AwesomeTCPEngine) Disconnect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.clientConn != nil {
		err := e.clientConn.Close()
		e.clientConn = nil
		log.Printf("[TCP Client :%d] 已发起 FIN 关闭连接", e.clientPort)
		return err
	}
	return nil
}

// BuildRawTCPHeaderAndChecksum 按照 RFC 9293 构造真实大端序 20 字节 TCP 首部 + 载荷并计算校验和
func BuildRawTCPHeaderAndChecksum(srcPort, dstPort uint16, seq, ack uint32, flags TCPFlags, win uint16, payload []byte) ([]byte, uint16) {
	totalLen := 20 + len(payload)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ack)

	buf[12] = 0x50 // Data Offset: 5 (20 bytes)
	var fb byte
	if flags.FIN {
		fb |= 0x01
	}
	if flags.SYN {
		fb |= 0x02
	}
	if flags.RST {
		fb |= 0x04
	}
	if flags.PSH {
		fb |= 0x08
	}
	if flags.ACK {
		fb |= 0x10
	}
	if flags.URG {
		fb |= 0x20
	}
	buf[13] = fb
	binary.BigEndian.PutUint16(buf[14:16], win)
	copy(buf[20:], payload)

	// 计算 16 位 TCP 伪首部 + 报文段反码求和校验和
	var sum uint32 = 0x7F00 + 0x0001 + 0x7F00 + 0x0001 + 0x0006 + uint32(totalLen)
	for i := 0; i < totalLen; i += 2 {
		w := uint32(buf[i]) << 8
		if i+1 < totalLen {
			w |= uint32(buf[i+1])
		}
		sum += w
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
	}
	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(buf[16:18], checksum)
	return buf, checksum
}

func (e *AwesomeTCPEngine) recordFrameLocked(dir string, srcPort, dstPort uint16, flags TCPFlags, relSeq, relAck uint32, payload []byte, note string) {
	e.pktID++
	rawSeq := e.clientISN + relSeq
	rawAck := e.serverISN + relAck
	if dir == "S2C" {
		rawSeq = e.serverISN + relSeq
		rawAck = e.clientISN + relAck
	}
	if !flags.ACK {
		rawAck = 0
	}

	rawBytes, csum := BuildRawTCPHeaderAndChecksum(srcPort, dstPort, rawSeq, rawAck, flags, 65535, payload)

	rec := PacketRecord{
		ID:          e.pktID,
		Timestamp:   time.Now().Format("15:04:05.000"),
		Direction:   dir,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Flags:       flags,
		RelSeq:      relSeq,
		RelAck:      relAck,
		RawSeq:      rawSeq,
		RawAck:      rawAck,
		WindowSize:  65535,
		Checksum:    fmt.Sprintf("0x%04X", csum),
		PayloadLen:  len(payload),
		PayloadText: string(payload),
		RawHex:      hex.EncodeToString(rawBytes),
		Note:        note,
	}
	e.packets = append(e.packets, rec)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

type sendReq struct {
	Message string `json:"message"`
}

func main() {
	cfg := ParseConfig()
	if cfg.DemoMode == "legacy" {
		runLegacy()
		return
	}
	lab, err := NewLab(cfg)
	if err != nil {
		log.Fatalf("启动协议实验室失败: %v", err)
	}
	if err := lab.Run(); err != nil {
		log.Fatalf("协议实验室运行失败: %v", err)
	}
}

// runLegacy keeps the original single-connection raw TCP teaching engine
// available for comparison with the real protocol lab.
func runLegacy() {
	engine := NewAwesomeTCPEngine()
	if err := engine.StartRealTCPServer(); err != nil {
		log.Fatalf("启动 TCP 服务端失败: %v", err)
	}

	mux := http.NewServeMux()

	// 1. 根路径直接返回内嵌的 awesome_tcp.html
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(embeddedUI)
	})

	// 2. 状态探针接口（前端加载时自动识别 Go 原生内核引擎已挂载）
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"engine":     "go-native-tcp",
			"serverAddr": fmt.Sprintf("127.0.0.1:%d", engine.serverPort),
		})
	})

	// 3. 真实发起 TCP 三次握手并默认发送 "hello"
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		err := engine.ConnectAndSendDefaultHello()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         err == nil,
			"clientPort": engine.clientPort,
		})
	})

	// 4. 客户端向真实 TCP Socket 发送载荷
	mux.HandleFunc("/api/client-send", func(w http.ResponseWriter, r *http.Request) {
		var req sendReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Message == "" {
			req.Message = "hello"
		}
		err := engine.ClientSend(req.Message, false)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": err == nil})
	})

	// 5. 服务端主动向真实 TCP Socket 推送载荷
	mux.HandleFunc("/api/server-send", func(w http.ResponseWriter, r *http.Request) {
		var req sendReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Message == "" {
			req.Message = "server_push"
		}
		err := engine.ServerSend(req.Message)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": err == nil})
	})

	// 6. 断开真实 TCP Socket
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		err := engine.Disconnect()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": err == nil})
	})

	// 7. 获取底层捕获的完整报文序列
	mux.HandleFunc("/api/packets", func(w http.ResponseWriter, r *http.Request) {
		engine.mu.Lock()
		defer engine.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(engine.packets)
	})

	uiAddr := "127.0.0.1:19527"
	log.Printf("================================================================")
	log.Printf("🚀 《了不起的TCP》本地原生引擎已就绪!")
	log.Printf("👉 真实 TCP 服务端监听地址: 127.0.0.1:%d", engine.serverPort)
	log.Printf("👉 可视化控制台访问地址:   http://%s", uiAddr)
	log.Printf("================================================================")

	go func() {
		time.Sleep(350 * time.Millisecond)
		openBrowser("http://" + uiAddr)
	}()
	log.Fatal(http.ListenAndServe(uiAddr, mux))
}
