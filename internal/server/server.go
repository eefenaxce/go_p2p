package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/auth"
	"github.com/eefenaxce/vlan-tool/internal/logger"
	"github.com/eefenaxce/vlan-tool/internal/protocol"
	"github.com/eefenaxce/vlan-tool/internal/stats"
)

type ServerConfig struct {
	ListenAddr    string
	ServerSecret  string
	EnableStats   bool
	MaxConnections int
}

type ClientConnection struct {
	conn       net.Conn
	nodeID     string
	sessionID  uint32
	ipAddress  string
	macAddress string
	lastActive time.Time
	mu         sync.Mutex
}

type Server struct {
	config       *ServerConfig
	listener     net.Listener
	connections  map[uint32]*ClientConnection
	authManager  *auth.AuthManager
	statsManager *stats.StatsManager
	mu           sync.RWMutex
	running      bool
	stopChan     chan struct{}
}

func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":8080"
	}

	if config.ServerSecret == "" {
		config.ServerSecret = "default-secret-change-me"
	}

	if config.MaxConnections == 0 {
		config.MaxConnections = 100
	}

	return &Server{
		config:       config,
		connections:  make(map[uint32]*ClientConnection),
		authManager:  auth.NewAuthManager(config.ServerSecret),
		statsManager: stats.NewStatsManager(),
		stopChan:     make(chan struct{}),
	}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("服务器已在运行")
	}
	s.running = true
	s.mu.Unlock()

	logger.Info("正在启动VLAN服务器...")

	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		logger.Errorf("监听失败: %v", err)
		return fmt.Errorf("监听失败: %w", err)
	}

	s.listener = listener
	logger.Infof("服务器已启动，监听地址: %s", s.config.ListenAddr)

	s.authManager.StartCleanupRoutine(1 * time.Minute)

	go s.acceptConnections()
	go s.statsMonitor()

	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return errors.New("服务器未运行")
	}
	s.running = false
	s.mu.Unlock()

	logger.Info("正在停止服务器...")

	close(s.stopChan)

	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	for sessionID, conn := range s.connections {
		conn.mu.Lock()
		if conn.conn != nil {
			conn.conn.Close()
		}
		conn.mu.Unlock()
		delete(s.connections, sessionID)
	}
	s.mu.Unlock()

	logger.Info("服务器已停止")

	return nil
}

func (s *Server) acceptConnections() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if s.running {
					logger.Errorf("接受连接失败: %v", err)
				}
				continue
			}

			s.mu.RLock()
			currentConnections := len(s.connections)
			s.mu.RUnlock()

			if currentConnections >= s.config.MaxConnections {
				logger.Warnf("连接数已达上限 %d，拒绝新连接", s.config.MaxConnections)
				conn.Close()
				continue
			}

			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger.Infof("新连接来自: %s", remoteAddr)

	sessionID := uint32(0)
	var clientConn *ClientConnection

	defer func() {
		if sessionID != 0 {
			s.authManager.Logout(sessionID)
			s.statsManager.UnregisterNode(clientConn.nodeID)

			s.mu.Lock()
			delete(s.connections, sessionID)
			s.mu.Unlock()

			logger.Infof("客户端断开连接: %s (会话ID: %d)", clientConn.nodeID, sessionID)
		}
	}()

	buf := make([]byte, protocol.MaxPacketSize)

	for {
		select {
		case <-s.stopChan:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					logger.Errorf("读取数据失败: %v", err)
				}
				return
			}

			if n == 0 {
				continue
			}

			packet, err := protocol.DeserializePacket(buf[:n])
			if err != nil {
				logger.Errorf("解析数据包失败: %v", err)
				continue
			}

			if !packet.Validate() {
				logger.Warn("数据包校验失败")
				continue
			}

			if err := s.handlePacket(conn, packet, &sessionID, &clientConn); err != nil {
				logger.Errorf("处理数据包失败: %v", err)
				return
			}
		}
	}
}

func (s *Server) handlePacket(conn net.Conn, packet *protocol.Packet, sessionID *uint32, clientConn **ClientConnection) error {
	switch packet.Header.Type {
	case protocol.PacketTypeAuth:
		return s.handleAuthPacket(conn, packet, sessionID, clientConn)
	case protocol.PacketTypeData:
		return s.handleDataPacket(packet, *sessionID)
	case protocol.PacketTypeControl:
		return s.handleControlPacket(packet, *sessionID)
	case protocol.PacketTypePing:
		return s.handlePingPacket(conn, packet, *sessionID)
	case protocol.PacketTypePong:
		return s.handlePongPacket(packet, *sessionID)
	case protocol.PacketTypeStats:
		return s.handleStatsPacket(packet, *sessionID)
	default:
		logger.Warnf("未知数据包类型: %d", packet.Header.Type)
		return nil
	}
}

func (s *Server) handleAuthPacket(conn net.Conn, packet *protocol.Packet, sessionID *uint32, clientConn **ClientConnection) error {
	authReq, err := protocol.DeserializeAuthRequest(packet.Body)
	if err != nil {
		logger.Errorf("解析认证请求失败: %v", err)
		return err
	}

	logger.Infof("收到认证请求: 节点ID=%s, IP=%s", authReq.NodeID, authReq.IPAddress)

	sid, err := s.authManager.Authenticate(authReq.NodeID, authReq.AuthToken, authReq.IPAddress, authReq.MacAddress)
	if err != nil {
		logger.Errorf("认证失败: %v", err)

		authResp := protocol.AuthResponse{
			Success:   false,
			Message:   err.Error(),
			SessionID: 0,
		}

		respBody, _ := protocol.SerializeAuthResponse(authResp)
		respPacket := protocol.NewPacket(protocol.PacketTypeAuth, respBody)
		respData, _ := respPacket.Serialize()

		conn.Write(respData)
		return err
	}

	node, _ := s.authManager.GetNodeBySession(sid)

	*sessionID = sid
	*clientConn = &ClientConnection{
		conn:       conn,
		nodeID:     node.NodeID,
		sessionID:  sid,
		ipAddress:  node.IPAddress,
		macAddress: node.MacAddress,
		lastActive: time.Now(),
	}

	s.mu.Lock()
	s.connections[sid] = *clientConn
	s.mu.Unlock()

	s.statsManager.RegisterNode(node.NodeID)

	authResp := protocol.AuthResponse{
		Success:    true,
		NodeID:     node.NodeID,
		SessionID:  sid,
		IPAddress:  node.IPAddress,
		SubnetMask: "255.255.255.0",
		Gateway:    "10.0.0.1",
		Message:    "认证成功",
	}

	respBody, _ := protocol.SerializeAuthResponse(authResp)
	respPacket := protocol.NewPacket(protocol.PacketTypeAuth, respBody)
	respData, _ := respPacket.Serialize()

	conn.Write(respData)

	logger.Infof("客户端认证成功: %s (会话ID: %d)", node.NodeID, sid)

	return nil
}

func (s *Server) handleDataPacket(packet *protocol.Packet, sessionID uint32) error {
	dataPacket, err := protocol.DeserializeDataPacket(packet.Body)
	if err != nil {
		logger.Errorf("解析数据包失败: %v", err)
		return err
	}

	sourceNodeID, err := s.authManager.ValidateSession(sessionID)
	if err != nil {
		logger.Errorf("无效的会话: %v", err)
		return err
	}

	s.statsManager.RecordSent(sourceNodeID, uint64(len(dataPacket.Data)))

	s.mu.RLock()
	destConn, exists := s.connections[sessionID]
	s.mu.RUnlock()

	if exists {
		destConn.mu.Lock()
		destConn.lastActive = time.Now()
		destConn.mu.Unlock()
	}

	s.mu.RLock()
	for sid, conn := range s.connections {
		if sid != sessionID {
			conn.mu.Lock()
			if conn.conn != nil {
				conn.conn.Write(packet.Body)
			}
			conn.mu.Unlock()

			s.statsManager.RecordReceived(conn.nodeID, uint64(len(dataPacket.Data)))
		}
	}
	s.mu.RUnlock()

	return nil
}

func (s *Server) handleControlPacket(packet *protocol.Packet, sessionID uint32) error {
	controlPacket, err := protocol.DeserializeControlPacket(packet.Body)
	if err != nil {
		logger.Errorf("解析控制包失败: %v", err)
		return err
	}

	switch controlPacket.ControlType {
	case protocol.ControlTypeHeartbeat:
		return s.authManager.UpdateHeartbeat(sessionID)
	case protocol.ControlTypeRegister:
		logger.Infof("节点注册: %s", controlPacket.NodeID)
	case protocol.ControlTypeUnregister:
		logger.Infof("节点注销: %s", controlPacket.NodeID)
	default:
		logger.Warnf("未知控制类型: %d", controlPacket.ControlType)
	}

	return nil
}

func (s *Server) handlePingPacket(conn net.Conn, packet *protocol.Packet, sessionID uint32) error {
	pingPacket, err := protocol.DeserializePingPacket(packet.Body)
	if err != nil {
		return err
	}

	pongPacket := protocol.PongPacket{
		Sequence:  pingPacket.Sequence,
		Timestamp: pingPacket.Timestamp,
		NodeID:    "server",
		RTT:       time.Now().UnixMilli() - pingPacket.Timestamp,
	}

	pongBody, _ := protocol.SerializePongPacket(pongPacket)
	pongProto := protocol.NewPacket(protocol.PacketTypePong, pongBody)
	pongData, _ := pongProto.Serialize()

	conn.Write(pongData)

	return nil
}

func (s *Server) handlePongPacket(packet *protocol.Packet, sessionID uint32) error {
	pongPacket, err := protocol.DeserializePongPacket(packet.Body)
	if err != nil {
		return err
	}

	logger.Debugf("收到Pong包: 序列号=%d, RTT=%dms", pongPacket.Sequence, pongPacket.RTT)

	return nil
}

func (s *Server) handleStatsPacket(packet *protocol.Packet, sessionID uint32) error {
	statsPacket, err := protocol.DeserializeStatsPacket(packet.Body)
	if err != nil {
		return err
	}

	logger.Debugf("收到统计包: 节点=%s, 发送=%d, 接收=%d", statsPacket.NodeID, statsPacket.BytesSent, statsPacket.BytesReceived)

	return nil
}

func (s *Server) statsMonitor() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			if s.config.EnableStats {
				s.statsManager.PrintSummary()
			}
		}
	}
}

func (s *Server) RegisterNode(nodeID, nodeName, authToken, ipAddress, macAddress string) error {
	return s.authManager.RegisterNode(nodeID, nodeName, authToken, ipAddress, macAddress)
}

func (s *Server) GetOnlineNodes() []*auth.Node {
	return s.authManager.GetOnlineNodes()
}

func (s *Server) GetConnectionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.connections)
}

func (s *Server) GetStats() *stats.TrafficStats {
	return s.statsManager.GetTrafficStats()
}

func (s *Server) BroadcastMessage(message []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, conn := range s.connections {
		conn.mu.Lock()
		if conn.conn != nil {
			conn.conn.Write(message)
		}
		conn.mu.Unlock()
	}

	return nil
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Server) GetServerInfo() map[string]interface{} {
	info := make(map[string]interface{})
	info["listen_addr"] = s.config.ListenAddr
	info["running"] = s.running
	info["connections"] = len(s.connections)
	info["max_connections"] = s.config.MaxConnections
	info["stats_enabled"] = s.config.EnableStats

	onlineNodes := s.authManager.GetOnlineNodes()
	info["online_nodes"] = len(onlineNodes)

	return info
}

func (s *Server) ExportConfig() ([]byte, error) {
	config := map[string]interface{}{
		"listen_addr":     s.config.ListenAddr,
		"max_connections": s.config.MaxConnections,
		"enable_stats":    s.config.EnableStats,
	}

	return json.MarshalIndent(config, "", "  ")
}
