package hotspotmem

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProfileData 表示一次 dump 的数据
type ProfileData struct {
	Timestamp time.Time
	Data      string
	Error     error
}

// JVMAttacher 用于与 JVM 进程通信
type JVMAttacher struct {
	pid     int
	nspid   int
	tmpPath string
}

// NewJVMAttacher 创建一个新的 JVM attacher
func NewJVMAttacher(pid int) (*JVMAttacher, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid hot spot mem profile PID: %d", pid)
	}

	// 获取进程的 namespace PID
	nspid, err := getNamespacePID(pid)
	if err != nil {
		nspid = pid // 如果获取失败，使用原始 PID
	}

	// 获取 /tmp 路径
	tmpPath := getTmpPath(pid)
	if err := ExtractEmbeddedLibrary(tmpPath); err != nil {
		return nil, fmt.Errorf("unable to extract lib : %v", err)
	}

	return &JVMAttacher{
		pid:     pid,
		nspid:   nspid,
		tmpPath: tmpPath,
	}, nil
}

// getNamespacePID 获取进程在其 namespace 中的 PID
func getNamespacePID(pid int) (int, error) {
	// 读取 /proc/pid/status 文件
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return pid, err
	}

	// 查找 NStgid 行
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "NStgid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// 最后一个字段是 namespace 中的 PID
				return strconv.Atoi(fields[len(fields)-1])
			}
		}
	}

	return pid, nil
}

// getTmpPath 获取进程的 /tmp 路径
func getTmpPath(pid int) string {
	// 尝试使用进程的 root/tmp
	procTmp := fmt.Sprintf("/proc/%d/root/tmp", pid)
	if _, err := os.Stat(procTmp); err == nil {
		return procTmp
	}
	return os.TempDir()
}

// checkSocket 检查 JVM attach socket 是否存在
func (j *JVMAttacher) checkSocket() bool {
	socketPath := fmt.Sprintf("%s/.java_pid%d", j.tmpPath, j.nspid)
	info, err := os.Stat(socketPath)
	if err != nil {
		return false
	}
	// 检查是否是 socket 文件
	return info.Mode()&os.ModeSocket != 0
}

// startAttachMechanism 启动 JVM 的 attach 机制
func (j *JVMAttacher) startAttachMechanism() error {
	// 创建 .attach_pid 文件
	attachFile := fmt.Sprintf("%s/.attach_pid%d", j.tmpPath, j.nspid)

	// 尝试在 /proc/pid/cwd 创建
	cwdAttachFile := fmt.Sprintf("/proc/%d/cwd/.attach_pid%d", j.nspid, j.nspid)
	f, err := os.OpenFile(cwdAttachFile, os.O_CREATE|os.O_WRONLY, 0660)
	if err == nil {
		_ = f.Close()
		attachFile = cwdAttachFile
	} else {
		// 在 /tmp 创建
		f, err = os.OpenFile(attachFile, os.O_CREATE|os.O_WRONLY, 0660)
		if err != nil {
			return fmt.Errorf("failed to create attach file: %w", err)
		}
		_ = f.Close()
	}

	defer os.Remove(attachFile)

	/*
		JVM 有一个内置的 Attach Listener 机制，但默认情况下这个监听线程可能没有启动。当 JVM 收到 SIGQUIT 信号时，它会：
		检查是否存在 .attach_pid<pid> 文件
		如果存在该文件，JVM 会启动 Attach Listener 线程
		Attach Listener 线程会创建一个 Unix Domain Socket（.java_pid<pid>）用于接收外部命令

		为什么是 SIGQUIT？
		SIGQUIT 在 JVM 中有特殊含义，通常用于触发线程 dump
		JVM 的 Signal Dispatcher 线程会捕获这个信号
		当检测到 .attach_pid 文件存在时，JVM 不会执行线程 dump，而是启动 Attach Listener
		这是 JVM 官方设计的 Attach 机制的一部分

		SIGQUIT 是安全的，JVM 专门处理了这个信号用于诊断和 attach 机制，不会导致进程退出。
		这也是为什么 async-profiler、jstack、jmap 等工具都使用这个信号来连接 JVM。
	*/
	process, err := os.FindProcess(j.pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}
	// 发送 SIGQUIT 信号给 JVM
	if err := process.Signal(syscall.SIGQUIT); err != nil {
		return fmt.Errorf("failed to send SIGQUIT: %w", err)
	}

	// 等待 socket 创建，最多等待 6 秒
	for i := 0; i < 300; i++ {
		if j.checkSocket() {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for JVM attach socket")
}

// connectSocket 连接到 JVM 的 attach socket
func (j *JVMAttacher) connectSocket() (net.Conn, error) {
	socketPath := fmt.Sprintf("%s/.java_pid%d", j.tmpPath, j.nspid)

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to socket %s: %w", socketPath, err)
	}

	return conn, nil
}

// writeCommand 向 socket 写入命令
func (j *JVMAttacher) writeCommand(conn net.Conn, args []string) error {
	var buf bytes.Buffer

	// 协议版本
	buf.WriteByte('1')
	buf.WriteByte(0)

	// 写入参数（最多 4 个）
	for i := 0; i < 4; i++ {
		if i < len(args) {
			buf.WriteString(args[i])
		}
		buf.WriteByte(0)
	}

	_, err := conn.Write(buf.Bytes())
	return err
}

// readResponse 读取 JVM 的响应
func (j *JVMAttacher) readResponse(conn net.Conn, isLoadCommand bool) (string, error) {
	var result bytes.Buffer
	buf := make([]byte, 8192)

	// 读取第一块数据
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if n == 0 {
		return "", fmt.Errorf("unexpected EOF reading response")
	}

	result.Write(buf[:n])

	// 对于 load 命令，读取所有数据
	if isLoadCommand {
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return "", err
			}
			if n == 0 {
				break
			}
			result.Write(buf[:n])
		}
	} else {
		// 对于其他命令，继续读取直到 EOF
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				break
			}
			if n == 0 {
				break
			}
			result.Write(buf[:n])
		}
	}

	return result.String(), nil
}

// executeCommand 执行 JVM attach 命令
func (j *JVMAttacher) executeCommand(args []string) (string, error) {
	// 检查 socket 是否存在，不存在则启动 attach 机制
	if !j.checkSocket() {
		if err := j.startAttachMechanism(); err != nil {
			return "", fmt.Errorf("failed to start attach mechanism: %w", err)
		}
	}

	// 连接到 socket
	conn, err := j.connectSocket()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 写入命令
	if err := j.writeCommand(conn, args); err != nil {
		return "", fmt.Errorf("failed to write command: %w", err)
	}

	// 读取响应
	isLoadCommand := len(args) > 0 && args[0] == "load"
	response, err := j.readResponse(conn, isLoadCommand)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return response, nil
}

// loadAgent 加载 async-profiler agent 并执行命令
func (j *JVMAttacher) loadAgent(agentArgs string) (string, error) {
	args := []string{
		"load",
		libPath,
		"true", // instrument = true
		agentArgs,
	}
	response, err := j.executeCommand(args)
	if err != nil {
		return "", err
	}
	// 解析响应码
	lines := strings.Split(response, "\n")
	if len(lines) < 1 {
		return "", fmt.Errorf("invalid response: %s", response)
	}

	// 第一行是返回码
	returnCode := strings.TrimSpace(lines[0])
	if returnCode != "0" {
		// 检查是否有 "return code:" 行
		for i, line := range lines {
			if strings.HasPrefix(line, "return code:") {
				code := strings.TrimSpace(strings.TrimPrefix(line, "return code:"))
				if code != "0" {
					errorMsg := ""
					if i+1 < len(lines) {
						errorMsg = strings.Join(lines[i+1:], "\n")
					}
					return "", fmt.Errorf("agent returned error code %s: %s", code, errorMsg)
				}
				break
			}
		}
	}
	return response, nil
}
