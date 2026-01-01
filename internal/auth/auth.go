package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/logger"
)

const (
	TokenLength     = 32
	SessionTimeout  = 30 * time.Minute
	HeartbeatInterval = 30 * time.Second
	MaxFailedAttempts = 5
	LockoutDuration   = 5 * time.Minute
)

var (
	ErrInvalidToken      = errors.New("无效的认证令牌")
	ErrSessionExpired    = errors.New("会话已过期")
	ErrNodeNotFound      = errors.New("节点未找到")
	ErrTooManyAttempts   = errors.New("尝试次数过多，账户已锁定")
	ErrAlreadyAuthenticated = errors.New("节点已认证")
)

type Node struct {
	NodeID     string
	NodeName   string
	AuthToken  string
	IPAddress  string
	MacAddress string
	SessionID  uint32
	LastSeen   time.Time
	IsOnline   bool
	FailedAttempts int
	LockedUntil time.Time
}

type AuthManager struct {
	nodes          map[string]*Node
	sessions       map[uint32]*Node
	nodeSecrets    map[string]string
	mu             sync.RWMutex
	nextSessionID  uint32
	serverSecret   string
}

func NewAuthManager(serverSecret string) *AuthManager {
	return &AuthManager{
		nodes:         make(map[string]*Node),
		sessions:      make(map[uint32]*Node),
		nodeSecrets:   make(map[string]string),
		nextSessionID: 1,
		serverSecret:  serverSecret,
	}
}

func (am *AuthManager) GenerateToken() (string, error) {
	bytes := make([]byte, TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("生成令牌失败: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func (am *AuthManager) RegisterNode(nodeID, nodeName, authToken, ipAddress, macAddress string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.nodes[nodeID]; exists {
		return fmt.Errorf("节点已存在: %s", nodeID)
	}

	node := &Node{
		NodeID:      nodeID,
		NodeName:    nodeName,
		AuthToken:   authToken,
		IPAddress:   ipAddress,
		MacAddress:  macAddress,
		SessionID:   0,
		LastSeen:    time.Now(),
		IsOnline:    false,
		FailedAttempts: 0,
	}

	am.nodes[nodeID] = node
	am.nodeSecrets[nodeID] = authToken

	logger.Infof("节点注册成功: %s (%s)", nodeID, nodeName)

	return nil
}

func (am *AuthManager) Authenticate(nodeID, authToken, ipAddress, macAddress string) (uint32, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	node, exists := am.nodes[nodeID]
	if !exists {
		return 0, ErrNodeNotFound
	}

	if time.Now().Before(node.LockedUntil) {
		return 0, ErrTooManyAttempts
	}

	expectedToken := am.nodeSecrets[nodeID]
	if authToken != expectedToken {
		node.FailedAttempts++
		if node.FailedAttempts >= MaxFailedAttempts {
			node.LockedUntil = time.Now().Add(LockoutDuration)
			logger.Warnf("节点 %s 因多次认证失败被锁定至 %s", nodeID, node.LockedUntil.Format("2006-01-02 15:04:05"))
		}
		logger.Warnf("节点 %s 认证失败: 无效的令牌 (尝试次数: %d)", nodeID, node.FailedAttempts)
		return 0, ErrInvalidToken
	}

	if node.IsOnline {
		logger.Warnf("节点 %s 已经在线，拒绝重复认证", nodeID)
		return 0, ErrAlreadyAuthenticated
	}

	node.FailedAttempts = 0
	node.LockedUntil = time.Time{}

	sessionID := am.nextSessionID
	am.nextSessionID++

	node.SessionID = sessionID
	node.IPAddress = ipAddress
	node.MacAddress = macAddress
	node.LastSeen = time.Now()
	node.IsOnline = true

	am.sessions[sessionID] = node

	logger.Infof("节点认证成功: %s (会话ID: %d, IP: %s)", nodeID, sessionID, ipAddress)

	return sessionID, nil
}

func (am *AuthManager) ValidateSession(sessionID uint32) (string, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	node, exists := am.sessions[sessionID]
	if !exists {
		return "", ErrSessionExpired
	}

	if time.Since(node.LastSeen) > SessionTimeout {
		return "", ErrSessionExpired
	}

	return node.NodeID, nil
}

func (am *AuthManager) UpdateHeartbeat(sessionID uint32) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	node, exists := am.sessions[sessionID]
	if !exists {
		return ErrSessionExpired
	}

	node.LastSeen = time.Now()

	return nil
}

func (am *AuthManager) Logout(sessionID uint32) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	node, exists := am.sessions[sessionID]
	if !exists {
		return ErrSessionExpired
	}

	node.IsOnline = false
	node.SessionID = 0

	delete(am.sessions, sessionID)

	logger.Infof("节点登出: %s (会话ID: %d)", node.NodeID, sessionID)

	return nil
}

func (am *AuthManager) GetNode(nodeID string) (*Node, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	node, exists := am.nodes[nodeID]
	if !exists {
		return nil, ErrNodeNotFound
	}

	return node, nil
}

func (am *AuthManager) GetNodeBySession(sessionID uint32) (*Node, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	node, exists := am.sessions[sessionID]
	if !exists {
		return nil, ErrSessionExpired
	}

	return node, nil
}

func (am *AuthManager) GetAllNodes() []*Node {
	am.mu.RLock()
	defer am.mu.RUnlock()

	nodes := make([]*Node, 0, len(am.nodes))
	for _, node := range am.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

func (am *AuthManager) GetOnlineNodes() []*Node {
	am.mu.RLock()
	defer am.mu.RUnlock()

	nodes := make([]*Node, 0)
	for _, node := range am.nodes {
		if node.IsOnline {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

func (am *AuthManager) RemoveNode(nodeID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	node, exists := am.nodes[nodeID]
	if !exists {
		return ErrNodeNotFound
	}

	if node.IsOnline && node.SessionID != 0 {
		delete(am.sessions, node.SessionID)
	}

	delete(am.nodes, nodeID)
	delete(am.nodeSecrets, nodeID)

	logger.Infof("节点已删除: %s", nodeID)

	return nil
}

func (am *AuthManager) CleanupExpiredSessions() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	expiredSessions := []uint32{}

	for sessionID, node := range am.sessions {
		if now.Sub(node.LastSeen) > SessionTimeout {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		node := am.sessions[sessionID]
		node.IsOnline = false
		node.SessionID = 0
		delete(am.sessions, sessionID)
		logger.Infof("清理过期会话: %s (会话ID: %d)", node.NodeID, sessionID)
	}

	if len(expiredSessions) > 0 {
		logger.Infof("已清理 %d 个过期会话", len(expiredSessions))
	}
}

func (am *AuthManager) StartCleanupRoutine(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			am.CleanupExpiredSessions()
		}
	}()

	logger.Infof("会话清理例程已启动，间隔: %v", interval)
}

func (am *AuthManager) GenerateNodeSecret(nodeID string) (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.nodes[nodeID]; !exists {
		return "", ErrNodeNotFound
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	secretStr := hex.EncodeToString(secret)
	am.nodeSecrets[nodeID] = secretStr

	logger.Infof("为节点 %s 生成新的密钥", nodeID)

	return secretStr, nil
}

func (am *AuthManager) VerifyNodeSecret(nodeID, secret string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	expectedSecret, exists := am.nodeSecrets[nodeID]
	if !exists {
		return false
	}

	return secret == expectedSecret
}

func (am *AuthManager) HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + am.serverSecret))
	return hex.EncodeToString(hash[:])
}

func (am *AuthManager) VerifyPassword(password, hash string) bool {
	return am.HashPassword(password) == hash
}

func (am *AuthManager) GetNodeCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.nodes)
}

func (am *AuthManager) GetOnlineCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.sessions)
}
