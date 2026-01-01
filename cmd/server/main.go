package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/eefenaxce/vlan-tool/internal/logger"
	"github.com/eefenaxce/vlan-tool/internal/server"
)

var (
	listenAddr     = flag.String("listen", ":8080", "监听地址 (格式: host:port)")
	serverSecret   = flag.String("secret", "default-secret", "服务器密钥")
	maxConnections = flag.Int("max-connections", 100, "最大连接数")
	enableStats    = flag.Bool("stats", true, "启用统计功能")
	logLevel       = flag.String("log-level", "INFO", "日志级别 (DEBUG/INFO/WARN/ERROR)")
	logPath        = flag.String("log-path", "logs", "日志目录路径")
)

func main() {
	flag.Parse()

	logLevelValue := parseLogLevel(*logLevel)
	logger.InitGlobalLogger("server", *logPath, logger.LogLevel(logLevelValue))

	logger.Info("========================================")
	logger.Info("VLAN 服务端启动")
	logger.Info("========================================")
	logger.Infof("监听地址: %s", *listenAddr)
	logger.Infof("最大连接数: %d", *maxConnections)
	logger.Infof("统计功能: %v", *enableStats)
	logger.Infof("日志级别: %s", *logLevel)
	logger.Info("========================================")

	serverConfig := &server.ServerConfig{
		ListenAddr:     *listenAddr,
		ServerSecret:   *serverSecret,
		EnableStats:    *enableStats,
		MaxConnections: *maxConnections,
	}

	srv, err := server.NewServer(serverConfig)
	if err != nil {
		logger.Errorf("创建服务器失败: %v", err)
		os.Exit(1)
	}

	if err := srv.RegisterNode("node1", "节点1", "token1", "10.0.0.2", "00:11:22:33:44:55"); err != nil {
		logger.Warnf("注册默认节点失败: %v", err)
	}

	if err := srv.RegisterNode("node2", "节点2", "token2", "10.0.0.3", "00:11:22:33:44:56"); err != nil {
		logger.Warnf("注册默认节点失败: %v", err)
	}

	if err := srv.RegisterNode("node3", "节点3", "token3", "10.0.0.4", "00:11:22:33:44:57"); err != nil {
		logger.Warnf("注册默认节点失败: %v", err)
	}

	if err := srv.Start(); err != nil {
		logger.Errorf("启动服务器失败: %v", err)
		os.Exit(1)
	}

	logger.Info("服务器已成功启动，等待客户端连接...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	logger.Info("收到停止信号，正在关闭服务器...")

	if err := srv.Stop(); err != nil {
		logger.Errorf("停止服务器失败: %v", err)
	}

	logger.Info("服务器已关闭")

	logger.GetGlobalLogger().Close()
}

func parseLogLevel(level string) int {
	switch level {
	case "DEBUG":
		return 0
	case "INFO":
		return 1
	case "WARN":
		return 2
	case "ERROR":
		return 3
	default:
		return 1
	}
}
