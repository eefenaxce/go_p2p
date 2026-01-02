package client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/logger"
	"github.com/eefenaxce/vlan-tool/internal/protocol"
	"github.com/eefenaxce/vlan-tool/internal/stats"
	"github.com/eefenaxce/vlan-tool/internal/tun"
)

type ClientConfig struct {
	ServerAddr    string
	NodeID        string
	NodeName      string
	AuthToken     string
	TUNName       string
	TUNIP         string
	TUNSubnet     string
	EnableStats   bool
	AutoReconnect bool
}

type Client struct {
	config       *ClientConfig
	conn         net.Conn
	tunDevice    *tun.TUNDevice
	statsManager *stats.StatsManager
	sessionID    uint32
	connected    bool
	mu           sync.RWMutex
	stopChan     chan struct{}
	pingSequence uint32
}

func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}

	if config.ServerAddr == "" {
		return nil, errors.New("服务器地址不能为空")
	}

	if config.NodeID == "" {
		id, _ := generateNodeID()
		config.NodeID = id
	}

	if config.NodeName == "" {
		config.NodeName = config.NodeID
	}

	if config.AuthToken == "" {
		token, _ := generateAuthToken()
		config.AuthToken = token
	}

	if config.TUNName == "" {
		config.TUNName = "vlan0"
	}

	if config.TUNIP == "" {
		config.TUNIP = "10.0.0.2"
	}

	if config.TUNSubnet == "" {
		config.TUNSubnet = "255.255.255.0"
	}

	return &Client{
		config:       config,
		statsManager: stats.NewStatsManager(),
		stopChan:     make(chan struct{}),
	}, nil
}

func generateNodeID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateAuthToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (c *Client) Connect() error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return errors.New("客户端已连接")
	}
	c.mu.Unlock()

	logger.Info("正在连接到服务器...")

	conn, err := net.DialTimeout("tcp", c.config.ServerAddr, 10*time.Second)
	if err != nil {
		logger.Errorf("连接服务器失败: %v", err)
		return fmt.Errorf("连接服务器失败: %w", err)
	}

	c.conn = conn
	logger.Infof("已连接到服务器: %s", c.config.ServerAddr)

	// 认证并获取服务端分配的IP
	if err := c.authenticate(); err != nil {
		c.conn.Close()
		return fmt.Errorf("认证失败: %w", err)
	}

	// 创建TUN设备（使用服务端分配的IP）
	if err := c.CreateTUNDevice(); err != nil {
		c.conn.Close()
		return fmt.Errorf("创建TUN设备失败: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	logger.Infof("客户端连接成功: %s (会话ID: %d)", c.config.NodeID, c.sessionID)

	go c.readLoop()
	go c.writeLoop()
	go c.heartbeatLoop()
	go c.statsMonitor()

	return nil
}

func (c *Client) authenticate() error {
	macAddr, _ := getMacAddress()

	authReq := protocol.AuthRequest{
		NodeID:     c.config.NodeID,
		AuthToken:  c.config.AuthToken,
		IPAddress:  "", // 客户端不再指定IP，由服务端分配
		MacAddress: macAddr,
		Version:    "1.0.0",
	}

	reqBody, err := protocol.SerializeAuthRequest(authReq)
	if err != nil {
		return err
	}

	reqPacket := protocol.NewPacket(protocol.PacketTypeAuth, reqBody)
	reqData, err := reqPacket.Serialize()
	if err != nil {
		return err
	}

	if _, err := c.conn.Write(reqData); err != nil {
		return err
	}

	buf := make([]byte, protocol.MaxPacketSize)
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.conn.Read(buf)
	if err != nil {
		return err
	}

	respPacket, err := protocol.DeserializePacket(buf[:n])
	if err != nil {
		return err
	}

	if !respPacket.Validate() {
		return errors.New("响应包校验失败")
	}

	authResp, err := protocol.DeserializeAuthResponse(respPacket.Body)
	if err != nil {
		return err
	}

	if !authResp.Success {
		return fmt.Errorf("认证失败: %s", authResp.Message)
	}

	c.sessionID = authResp.SessionID
	c.statsManager.RegisterNode(c.config.NodeID)

	// 保存服务端分配的IP地址和子网掩码
	c.config.TUNIP = authResp.IPAddress
	c.config.TUNSubnet = authResp.SubnetMask

	logger.Infof("认证成功，分配IP: %s, 子网掩码: %s, 网关: %s",
		authResp.IPAddress, authResp.SubnetMask, authResp.Gateway)

	return nil
}

func (c *Client) Disconnect() error {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return errors.New("客户端未连接")
	}
	c.connected = false
	c.mu.Unlock()

	logger.Info("正在断开连接...")

	close(c.stopChan)

	if c.conn != nil {
		c.conn.Close()
	}

	if c.tunDevice != nil {
		c.tunDevice.Close()
	}

	logger.Info("客户端已断开连接")

	return nil
}

func (c *Client) readLoop() {
	logger.Debug("启动读取循环")
	defer logger.Debug("读取循环已停止")

	buf := make([]byte, protocol.MaxPacketSize)

	for {
		select {
		case <-c.stopChan:
			return
		default:
			c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := c.conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					logger.Errorf("读取数据失败: %v", err)
				}
				c.handleDisconnect()
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

			if err := c.handlePacket(packet); err != nil {
				logger.Errorf("处理数据包失败: %v", err)
			}
		}
	}
}

func (c *Client) writeLoop() {
	logger.Debug("启动写入循环")
	defer logger.Debug("写入循环已停止")

	if c.tunDevice == nil {
		return
	}

	// 计算最大可用数据大小：MaxPacketSize - HeaderSize - JSON序列化开销
	// 预留200字节用于JSON序列化开销（根据实际情况调整）
	maxDataSize := protocol.MaxPacketSize - protocol.HeaderSize - 200

	for {
		select {
		case <-c.stopChan:
			return
		case data := <-c.tunDevice.GetReadChannel():
			if c.conn != nil {
				// 检查并截断数据，确保序列化后的数据包不会超过大小限制
				if len(data) > maxDataSize {
					logger.Warnf("数据大小超过限制，截断数据: %d -> %d", len(data), maxDataSize)
					data = data[:maxDataSize]
				}

				dataPacket := protocol.DataPacket{
					SourceNodeID: c.config.NodeID,
					DestNodeID:   "",
					Data:         data,
				}

				body, err := protocol.SerializeDataPacket(dataPacket)
				if err != nil {
					logger.Errorf("序列化数据包失败: %v", err)
					continue
				}

				packet := protocol.NewPacket(protocol.PacketTypeData, body)
				packetData, err := packet.Serialize()
				if err != nil {
					logger.Errorf("序列化数据包失败: %v", err)
					continue
				}

				if _, err := c.conn.Write(packetData); err != nil {
					logger.Errorf("发送数据失败: %v", err)
					continue
				}

				c.statsManager.RecordSent(c.config.NodeID, uint64(len(data)))
			}
		}
	}
}

func (c *Client) heartbeatLoop() {
	logger.Debug("启动心跳循环")
	defer logger.Debug("心跳循环已停止")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				logger.Errorf("发送心跳失败: %v", err)
			}
		}
	}
}

func (c *Client) sendHeartbeat() error {
	controlPacket := protocol.ControlPacket{
		ControlType: protocol.ControlTypeHeartbeat,
		NodeID:      c.config.NodeID,
		Data:        map[string]interface{}{},
	}

	body, err := protocol.SerializeControlPacket(controlPacket)
	if err != nil {
		return err
	}

	packet := protocol.NewPacket(protocol.PacketTypeControl, body)
	packetData, err := packet.Serialize()
	if err != nil {
		return err
	}

	if _, err := c.conn.Write(packetData); err != nil {
		return err
	}

	logger.Debug("心跳已发送")

	return nil
}

func (c *Client) handlePacket(packet *protocol.Packet) error {
	switch packet.Header.Type {
	case protocol.PacketTypeAuth:
		return c.handleAuthResponse(packet)
	case protocol.PacketTypeData:
		return c.handleDataPacket(packet)
	case protocol.PacketTypeControl:
		return c.handleControlPacket(packet)
	case protocol.PacketTypePing:
		return c.handlePingPacket(packet)
	case protocol.PacketTypePong:
		return c.handlePongPacket(packet)
	default:
		logger.Warnf("未知数据包类型: %d", packet.Header.Type)
		return nil
	}
}

func (c *Client) handleAuthResponse(packet *protocol.Packet) error {
	authResp, err := protocol.DeserializeAuthResponse(packet.Body)
	if err != nil {
		return err
	}

	if authResp.Success {
		c.sessionID = authResp.SessionID
		logger.Infof("认证成功: %s (会话ID: %d)", authResp.NodeID, authResp.SessionID)
	} else {
		logger.Errorf("认证失败: %s", authResp.Message)
	}

	return nil
}

func (c *Client) handleDataPacket(packet *protocol.Packet) error {
	dataPacket, err := protocol.DeserializeDataPacket(packet.Body)
	if err != nil {
		return err
	}

	c.statsManager.RecordReceived(c.config.NodeID, uint64(len(dataPacket.Data)))

	if c.tunDevice != nil {
		if err := c.tunDevice.Write(dataPacket.Data); err != nil {
			logger.Errorf("写入TUN设备失败: %v", err)
		}
	}

	return nil
}

func (c *Client) handleControlPacket(packet *protocol.Packet) error {
	controlPacket, err := protocol.DeserializeControlPacket(packet.Body)
	if err != nil {
		return err
	}

	switch controlPacket.ControlType {
	case protocol.ControlTypeHeartbeat:
		logger.Debug("收到心跳响应")
	default:
		logger.Warnf("未知控制类型: %d", controlPacket.ControlType)
	}

	return nil
}

func (c *Client) handlePingPacket(packet *protocol.Packet) error {
	pingPacket, err := protocol.DeserializePingPacket(packet.Body)
	if err != nil {
		return err
	}

	pongPacket := protocol.PongPacket{
		Sequence:  pingPacket.Sequence,
		Timestamp: pingPacket.Timestamp,
		NodeID:    c.config.NodeID,
		RTT:       time.Now().UnixMilli() - pingPacket.Timestamp,
	}

	pongBody, _ := protocol.SerializePongPacket(pongPacket)
	pongProto := protocol.NewPacket(protocol.PacketTypePong, pongBody)
	pongData, _ := pongProto.Serialize()

	c.conn.Write(pongData)

	return nil
}

func (c *Client) handlePongPacket(packet *protocol.Packet) error {
	pongPacket, err := protocol.DeserializePongPacket(packet.Body)
	if err != nil {
		return err
	}

	logger.Debugf("收到Pong包: 序列号=%d, RTT=%dms", pongPacket.Sequence, pongPacket.RTT)

	return nil
}

func (c *Client) handleDisconnect() {
	c.mu.Lock()
	if c.connected {
		c.connected = false
		logger.Warn("与服务器的连接已断开")

		if c.config.AutoReconnect {
			go c.reconnect()
		}
	}
	c.mu.Unlock()
}

func (c *Client) reconnect() {
	logger.Info("尝试重新连接...")

	for i := 0; i < 5; i++ {
		time.Sleep(time.Duration(i+1) * 5 * time.Second)

		if err := c.Connect(); err == nil {
			logger.Info("重新连接成功")
			return
		}

		logger.Warnf("重新连接失败，尝试 %d/5", i+1)
	}

	logger.Error("重新连接失败，已达到最大尝试次数")
}

func (c *Client) statsMonitor() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			if c.config.EnableStats {
				c.statsManager.PrintSummary()
			}
		}
	}
}

func (c *Client) CreateTUNDevice() error {
	tunConfig := &tun.TUNConfig{
		Name:       c.config.TUNName,
		MTU:        1500,
		IPAddress:  c.config.TUNIP,
		SubnetMask: c.config.TUNSubnet,
	}

	device, err := tun.NewTUNDevice(tunConfig)
	if err != nil {
		return err
	}

	if err := device.Create(); err != nil {
		return err
	}

	if err := device.Start(); err != nil {
		return err
	}

	c.tunDevice = device
	logger.Infof("TUN设备创建成功: %s (%s)", device.GetName(), device.GetIPAddress().String())

	return nil
}

func (c *Client) Ping(nodeID string) (time.Duration, error) {
	c.pingSequence++

	pingPacket := protocol.PingPacket{
		Sequence:  c.pingSequence,
		Timestamp: time.Now().UnixMilli(),
		NodeID:    c.config.NodeID,
	}

	pingBody, _ := protocol.SerializePingPacket(pingPacket)
	pingProto := protocol.NewPacket(protocol.PacketTypePing, pingBody)
	pingData, _ := pingProto.Serialize()

	if _, err := c.conn.Write(pingData); err != nil {
		return 0, err
	}

	return 0, nil
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *Client) GetSessionID() uint32 {
	return c.sessionID
}

func (c *Client) GetStats() *stats.TrafficStats {
	return c.statsManager.GetTrafficStats()
}

func getMacAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if len(iface.HardwareAddr) >= 6 {
			return iface.HardwareAddr.String(), nil
		}
	}

	return "00:00:00:00:00:00", nil
}
