package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/logger"
	"github.com/eefenaxce/vlan-tool/internal/protocol"
)

type DiscoveryConfig struct {
	BroadcastAddr string
	BroadcastPort int
	Interval      time.Duration
	Timeout       time.Duration
}

type NodeInfo struct {
	NodeID    string
	NodeName  string
	IPAddress string
	Port      int
	Version   string
	LastSeen  time.Time
}

type DiscoveryService struct {
	config      *DiscoveryConfig
	nodeID      string
	nodeName    string
	listener    net.PacketConn
	nodes       map[string]*NodeInfo
	mu          sync.RWMutex
	running     bool
	stopChan    chan struct{}
	onNodeFound func(*NodeInfo)
}

func NewDiscoveryService(config *DiscoveryConfig, nodeID, nodeName string) *DiscoveryService {
	if config == nil {
		config = &DiscoveryConfig{
			BroadcastAddr: "239.255.255.250",
			BroadcastPort: 1900,
			Interval:      30 * time.Second,
			Timeout:       5 * time.Minute,
		}
	}

	return &DiscoveryService{
		config:   config,
		nodeID:   nodeID,
		nodeName: nodeName,
		nodes:    make(map[string]*NodeInfo),
		stopChan: make(chan struct{}),
	}
}

func (ds *DiscoveryService) Start() error {
	ds.mu.Lock()
	if ds.running {
		ds.mu.Unlock()
		return fmt.Errorf("发现服务已在运行")
	}
	ds.running = true
	ds.mu.Unlock()

	logger.Info("正在启动节点发现服务...")

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ds.config.BroadcastAddr, ds.config.BroadcastPort))
	if err != nil {
		logger.Errorf("解析UDP地址失败: %v", err)
		return fmt.Errorf("解析UDP地址失败: %w", err)
	}

	listener, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		logger.Errorf("监听多播失败: %v", err)
		return fmt.Errorf("监听多播失败: %w", err)
	}

	ds.listener = listener
	logger.Infof("节点发现服务已启动，监听地址: %s", addr.String())

	go ds.listenLoop()
	go ds.broadcastLoop()
	go ds.cleanupLoop()

	return nil
}

func (ds *DiscoveryService) Stop() error {
	ds.mu.Lock()
	if !ds.running {
		ds.mu.Unlock()
		return fmt.Errorf("发现服务未运行")
	}
	ds.running = false
	ds.mu.Unlock()

	logger.Info("正在停止节点发现服务...")

	close(ds.stopChan)

	if ds.listener != nil {
		ds.listener.Close()
	}

	logger.Info("节点发现服务已停止")

	return nil
}

func (ds *DiscoveryService) listenLoop() {
	logger.Debug("启动发现监听循环")
	defer logger.Debug("发现监听循环已停止")

	buf := make([]byte, 1024)

	for {
		select {
		case <-ds.stopChan:
			return
		default:
			ds.listener.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := ds.listener.ReadFrom(buf)
			if err != nil {
				if !ds.running {
					return
				}
				continue
			}

			if n == 0 {
				continue
			}

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}

			ds.handleDiscoveryPacket(buf[:n], udpAddr)
		}
	}
}

func (ds *DiscoveryService) handleDiscoveryPacket(data []byte, addr *net.UDPAddr) {
	if len(data) == 0 || data[0] != '{' {
		return
	}

	var discoveryPacket protocol.DiscoveryPacket
	if err := json.Unmarshal(data, &discoveryPacket); err != nil {
		return
	}

	if discoveryPacket.NodeID == ds.nodeID {
		return
	}

	logger.Debugf("收到发现包: 节点ID=%s, 地址=%s:%d", discoveryPacket.NodeID, addr.IP.String(), addr.Port)

	nodeInfo := &NodeInfo{
		NodeID:    discoveryPacket.NodeID,
		NodeName:  discoveryPacket.NodeName,
		IPAddress: addr.IP.String(),
		Port:      addr.Port,
		Version:   discoveryPacket.Version,
		LastSeen:  time.Now(),
	}

	ds.mu.Lock()
	ds.nodes[discoveryPacket.NodeID] = nodeInfo
	ds.mu.Unlock()

	logger.Infof("发现新节点: %s (%s) at %s:%d", discoveryPacket.NodeID, discoveryPacket.NodeName, addr.IP.String(), addr.Port)

	if ds.onNodeFound != nil {
		go ds.onNodeFound(nodeInfo)
	}
}

func (ds *DiscoveryService) broadcastLoop() {
	logger.Debug("启动发现广播循环")
	defer logger.Debug("发现广播循环已停止")

	ticker := time.NewTicker(ds.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ds.stopChan:
			return
		case <-ticker.C:
			ds.broadcastDiscovery()
		}
	}
}

func (ds *DiscoveryService) broadcastDiscovery() {
	discoveryPacket := protocol.DiscoveryPacket{
		NodeID:    ds.nodeID,
		NodeName:  ds.nodeName,
		IPAddress: ds.getLocalIP(),
		Port:      ds.config.BroadcastPort,
		Version:   "1.0.0",
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(discoveryPacket)
	if err != nil {
		logger.Errorf("序列化发现包失败: %v", err)
		return
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ds.config.BroadcastAddr, ds.config.BroadcastPort))
	if err != nil {
		logger.Errorf("解析广播地址失败: %v", err)
		return
	}

	if _, err := ds.listener.WriteTo(data, addr); err != nil {
		logger.Errorf("发送发现包失败: %v", err)
		return
	}

	logger.Debug("已广播发现包")
}

func (ds *DiscoveryService) cleanupLoop() {
	logger.Debug("启动清理循环")
	defer logger.Debug("清理循环已停止")

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ds.stopChan:
			return
		case <-ticker.C:
			ds.cleanupStaleNodes()
		}
	}
}

func (ds *DiscoveryService) cleanupStaleNodes() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	now := time.Now()
	staleNodes := []string{}

	for nodeID, node := range ds.nodes {
		if now.Sub(node.LastSeen) > ds.config.Timeout {
			staleNodes = append(staleNodes, nodeID)
		}
	}

	for _, nodeID := range staleNodes {
		delete(ds.nodes, nodeID)
		logger.Infof("清理过期节点: %s", nodeID)
	}

	if len(staleNodes) > 0 {
		logger.Infof("已清理 %d 个过期节点", len(staleNodes))
	}
}

func (ds *DiscoveryService) GetNodes() []*NodeInfo {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	nodes := make([]*NodeInfo, 0, len(ds.nodes))
	for _, node := range ds.nodes {
		nodes = append(nodes, &NodeInfo{
			NodeID:    node.NodeID,
			NodeName:  node.NodeName,
			IPAddress: node.IPAddress,
			Port:      node.Port,
			Version:   node.Version,
			LastSeen:  node.LastSeen,
		})
	}

	return nodes
}

func (ds *DiscoveryService) GetNode(nodeID string) (*NodeInfo, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	node, exists := ds.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("节点未找到: %s", nodeID)
	}

	return &NodeInfo{
		NodeID:    node.NodeID,
		NodeName:  node.NodeName,
		IPAddress: node.IPAddress,
		Port:      node.Port,
		Version:   node.Version,
		LastSeen:  node.LastSeen,
	}, nil
}

func (ds *DiscoveryService) GetNodeCount() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.nodes)
}

func (ds *DiscoveryService) SetNodeFoundCallback(callback func(*NodeInfo)) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.onNodeFound = callback
}

func (ds *DiscoveryService) getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return "127.0.0.1"
}

func (ds *DiscoveryService) IsRunning() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.running
}

func (ds *DiscoveryService) PrintNodeList() {
	nodes := ds.GetNodes()

	logger.Info("========== 发现的节点列表 ==========")
	if len(nodes) == 0 {
		logger.Info("暂无发现的节点")
	} else {
		for _, node := range nodes {
			logger.Infof("节点ID: %s", node.NodeID)
			logger.Infof("  名称: %s", node.NodeName)
			logger.Infof("  地址: %s:%d", node.IPAddress, node.Port)
			logger.Infof("  版本: %s", node.Version)
			logger.Infof("  最后发现: %s", node.LastSeen.Format("2006-01-02 15:04:05"))
		}
	}
	logger.Info("==================================")
}
