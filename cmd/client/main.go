package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/client"
	"github.com/eefenaxce/vlan-tool/internal/discovery"
	"github.com/eefenaxce/vlan-tool/internal/logger"
)

var (
	serverAddr      = flag.String("server", "", "服务器地址 (格式: host:port)")
	nodeID          = flag.String("node-id", "", "节点ID")
	nodeName        = flag.String("node-name", "", "节点名称")
	authToken       = flag.String("token", "", "认证令牌")
	tunName         = flag.String("tun", "vlan0", "虚拟网卡名称")
	tunIP           = flag.String("tun-ip", "10.0.0.2", "虚拟网卡IP地址")
	tunSubnet       = flag.String("tun-subnet", "255.255.255.0", "虚拟网卡子网掩码")
	logLevel        = flag.String("log-level", "INFO", "日志级别 (DEBUG/INFO/WARN/ERROR)")
	logPath         = flag.String("log-path", "logs", "日志目录路径")
	enableStats     = flag.Bool("stats", true, "启用统计功能")
	autoReconnect   = flag.Bool("auto-reconnect", true, "启用自动重连")
	enableDiscovery = flag.Bool("discovery", false, "启用节点发现")
)

func main() {
	flag.Parse()

	if *serverAddr == "" {
		fmt.Println("错误: 必须指定服务器地址")
		fmt.Println("使用 -server 参数")
		os.Exit(1)
	}

	logLevelValue := parseLogLevel(*logLevel)
	logger.InitGlobalLogger("client", *logPath, logger.LogLevel(logLevelValue))

	logger.Info("========================================")
	logger.Info("VLAN 客户端启动")
	logger.Info("========================================")
	logger.Infof("服务器地址: %s", *serverAddr)
	logger.Infof("节点ID: %s", *nodeID)
	logger.Infof("节点名称: %s", *nodeName)
	logger.Infof("虚拟网卡: %s (%s)", *tunName, *tunIP)
	logger.Infof("统计功能: %v", *enableStats)
	logger.Infof("自动重连: %v", *autoReconnect)
	logger.Infof("节点发现: %v", *enableDiscovery)
	logger.Infof("日志级别: %s", *logLevel)
	logger.Info("========================================")

	clientConfig := &client.ClientConfig{
		ServerAddr:    *serverAddr,
		NodeID:        *nodeID,
		NodeName:      *nodeName,
		AuthToken:     *authToken,
		TUNName:       *tunName,
		TUNIP:         *tunIP,
		TUNSubnet:     *tunSubnet,
		EnableStats:   *enableStats,
		AutoReconnect: *autoReconnect,
	}

	cli, err := client.NewClient(clientConfig)
	if err != nil {
		logger.Errorf("创建客户端失败: %v", err)
		os.Exit(1)
	}

	if err := cli.CreateTUNDevice(); err != nil {
		logger.Errorf("创建TUN设备失败: %v", err)
		logger.Warn("继续运行，但虚拟网卡功能不可用")
	}

	if err := cli.Connect(); err != nil {
		logger.Errorf("连接服务器失败: %v", err)
		os.Exit(1)
	}

	logger.Info("客户端已成功连接到服务器")

	var discoveryService *discovery.DiscoveryService
	if *enableDiscovery {
		discoveryConfig := &discovery.DiscoveryConfig{
			BroadcastAddr: "239.255.255.250",
			BroadcastPort: 1900,
			Interval:      30 * time.Second,
			Timeout:       5 * time.Minute,
		}

		discoveryService = discovery.NewDiscoveryService(
			discoveryConfig,
			clientConfig.NodeID,
			clientConfig.NodeName,
		)

		if err := discoveryService.Start(); err != nil {
			logger.Warnf("启动节点发现服务失败: %v", err)
		} else {
			logger.Info("节点发现服务已启动")

			discoveryService.SetNodeFoundCallback(func(node *discovery.NodeInfo) {
				logger.Infof("发现新节点: %s (%s) at %s:%d", node.NodeID, node.NodeName, node.IPAddress, node.Port)
			})
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("客户端正在运行，按 Ctrl+C 退出...")

	<-sigChan

	logger.Info("收到停止信号，正在关闭客户端...")

	if discoveryService != nil {
		if err := discoveryService.Stop(); err != nil {
			logger.Errorf("停止节点发现服务失败: %v", err)
		}
	}

	if err := cli.Disconnect(); err != nil {
		logger.Errorf("断开连接失败: %v", err)
	}

	logger.Info("客户端已关闭")

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
