package stats

import (
	"sync"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/logger"
)

type NodeStats struct {
	NodeID          string
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	Errors          uint64
	LastSeen        time.Time
	StartTime       time.Time
}

type TrafficStats struct {
	TotalBytesSent     uint64
	TotalBytesReceived uint64
	TotalPacketsSent   uint64
	TotalPacketsReceived uint64
	TotalErrors        uint64
	StartTime          time.Time
}

type StatsManager struct {
	nodeStats  map[string]*NodeStats
	traffic    *TrafficStats
	mu         sync.RWMutex
}

func NewStatsManager() *StatsManager {
	return &StatsManager{
		nodeStats: make(map[string]*NodeStats),
		traffic: &TrafficStats{
			StartTime: time.Now(),
		},
	}
}

func (sm *StatsManager) RegisterNode(nodeID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.nodeStats[nodeID]; !exists {
		sm.nodeStats[nodeID] = &NodeStats{
			NodeID:    nodeID,
			StartTime: time.Now(),
			LastSeen:  time.Now(),
		}
		logger.Infof("注册节点统计: %s", nodeID)
	}
}

func (sm *StatsManager) UnregisterNode(nodeID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.nodeStats[nodeID]; exists {
		delete(sm.nodeStats, nodeID)
		logger.Infof("注销节点统计: %s", nodeID)
	}
}

func (sm *StatsManager) RecordSent(nodeID string, bytes uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if stats, exists := sm.nodeStats[nodeID]; exists {
		stats.BytesSent += bytes
		stats.PacketsSent++
		stats.LastSeen = time.Now()
	}

	sm.traffic.TotalBytesSent += bytes
	sm.traffic.TotalPacketsSent++
}

func (sm *StatsManager) RecordReceived(nodeID string, bytes uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if stats, exists := sm.nodeStats[nodeID]; exists {
		stats.BytesReceived += bytes
		stats.PacketsReceived++
		stats.LastSeen = time.Now()
	}

	sm.traffic.TotalBytesReceived += bytes
	sm.traffic.TotalPacketsReceived++
}

func (sm *StatsManager) RecordError(nodeID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if stats, exists := sm.nodeStats[nodeID]; exists {
		stats.Errors++
	}

	sm.traffic.TotalErrors++
}

func (sm *StatsManager) GetNodeStats(nodeID string) (*NodeStats, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats, exists := sm.nodeStats[nodeID]
	if !exists {
		return nil, nil
	}

	return &NodeStats{
		NodeID:          stats.NodeID,
		BytesSent:       stats.BytesSent,
		BytesReceived:   stats.BytesReceived,
		PacketsSent:     stats.PacketsSent,
		PacketsReceived: stats.PacketsReceived,
		Errors:          stats.Errors,
		LastSeen:        stats.LastSeen,
		StartTime:       stats.StartTime,
	}, nil
}

func (sm *StatsManager) GetAllNodeStats() []*NodeStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := make([]*NodeStats, 0, len(sm.nodeStats))
	for _, s := range sm.nodeStats {
		stats = append(stats, &NodeStats{
			NodeID:          s.NodeID,
			BytesSent:       s.BytesSent,
			BytesReceived:   s.BytesReceived,
			PacketsSent:     s.PacketsSent,
			PacketsReceived: s.PacketsReceived,
			Errors:          s.Errors,
			LastSeen:        s.LastSeen,
			StartTime:       s.StartTime,
		})
	}

	return stats
}

func (sm *StatsManager) GetTrafficStats() *TrafficStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return &TrafficStats{
		TotalBytesSent:     sm.traffic.TotalBytesSent,
		TotalBytesReceived: sm.traffic.TotalBytesReceived,
		TotalPacketsSent:   sm.traffic.TotalPacketsSent,
		TotalPacketsReceived: sm.traffic.TotalPacketsReceived,
		TotalErrors:        sm.traffic.TotalErrors,
		StartTime:          sm.traffic.StartTime,
	}
}

func (sm *StatsManager) ResetNodeStats(nodeID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if stats, exists := sm.nodeStats[nodeID]; exists {
		stats.BytesSent = 0
		stats.BytesReceived = 0
		stats.PacketsSent = 0
		stats.PacketsReceived = 0
		stats.Errors = 0
		stats.StartTime = time.Now()

		logger.Infof("重置节点统计: %s", nodeID)
	}
}

func (sm *StatsManager) ResetAllStats() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, stats := range sm.nodeStats {
		stats.BytesSent = 0
		stats.BytesReceived = 0
		stats.PacketsSent = 0
		stats.PacketsReceived = 0
		stats.Errors = 0
		stats.StartTime = time.Now()
	}

	sm.traffic.TotalBytesSent = 0
	sm.traffic.TotalBytesReceived = 0
	sm.traffic.TotalPacketsSent = 0
	sm.traffic.TotalPacketsReceived = 0
	sm.traffic.TotalErrors = 0
	sm.traffic.StartTime = time.Now()

	logger.Info("重置所有统计数据")
}

func (sm *StatsManager) GetUptime() time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return time.Since(sm.traffic.StartTime)
}

func (sm *StatsManager) GetNodeUptime(nodeID string) time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if stats, exists := sm.nodeStats[nodeID]; exists {
		return time.Since(stats.StartTime)
	}

	return 0
}

func (sm *StatsManager) GetThroughput() (float64, float64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	uptime := time.Since(sm.traffic.StartTime).Seconds()
	if uptime == 0 {
		return 0, 0
	}

	sendThroughput := float64(sm.traffic.TotalBytesSent) / uptime
	recvThroughput := float64(sm.traffic.TotalBytesReceived) / uptime

	return sendThroughput, recvThroughput
}

func (sm *StatsManager) GetNodeThroughput(nodeID string) (float64, float64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats, exists := sm.nodeStats[nodeID]
	if !exists {
		return 0, 0
	}

	uptime := time.Since(stats.StartTime).Seconds()
	if uptime == 0 {
		return 0, 0
	}

	sendThroughput := float64(stats.BytesSent) / uptime
	recvThroughput := float64(stats.BytesReceived) / uptime

	return sendThroughput, recvThroughput
}

func (sm *StatsManager) GetErrorRate() float64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	totalPackets := sm.traffic.TotalPacketsSent + sm.traffic.TotalPacketsReceived
	if totalPackets == 0 {
		return 0
	}

	return float64(sm.traffic.TotalErrors) / float64(totalPackets) * 100
}

func (sm *StatsManager) GetNodeErrorRate(nodeID string) float64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats, exists := sm.nodeStats[nodeID]
	if !exists {
		return 0
	}

	totalPackets := stats.PacketsSent + stats.PacketsReceived
	if totalPackets == 0 {
		return 0
	}

	return float64(stats.Errors) / float64(totalPackets) * 100
}

func (sm *StatsManager) PrintSummary() {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	traffic := sm.traffic
	uptime := time.Since(traffic.StartTime)

	logger.Info("========== 统计摘要 ==========")
	logger.Infof("运行时间: %v", uptime.Round(time.Second))
	logger.Infof("发送字节数: %d", traffic.TotalBytesSent)
	logger.Infof("接收字节数: %d", traffic.TotalBytesReceived)
	logger.Infof("发送包数: %d", traffic.TotalPacketsSent)
	logger.Infof("接收包数: %d", traffic.TotalPacketsReceived)
	logger.Infof("错误数: %d", traffic.TotalErrors)
	logger.Infof("在线节点数: %d", len(sm.nodeStats))

	sendThroughput, recvThroughput := sm.GetThroughput()
	logger.Infof("发送吞吐量: %.2f B/s", sendThroughput)
	logger.Infof("接收吞吐量: %.2f B/s", recvThroughput)

	errorRate := sm.GetErrorRate()
	logger.Infof("错误率: %.2f%%", errorRate)
	logger.Info("==============================")
}

func (sm *StatsManager) PrintNodeSummary(nodeID string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats, exists := sm.nodeStats[nodeID]
	if !exists {
		logger.Warnf("节点统计不存在: %s", nodeID)
		return
	}

	uptime := time.Since(stats.StartTime)

	logger.Infof("========== 节点统计: %s ==========", nodeID)
	logger.Infof("运行时间: %v", uptime.Round(time.Second))
	logger.Infof("发送字节数: %d", stats.BytesSent)
	logger.Infof("接收字节数: %d", stats.BytesReceived)
	logger.Infof("发送包数: %d", stats.PacketsSent)
	logger.Infof("接收包数: %d", stats.PacketsReceived)
	logger.Infof("错误数: %d", stats.Errors)
	logger.Infof("最后活动时间: %s", stats.LastSeen.Format("2006-01-02 15:04:05"))

	sendThroughput, recvThroughput := sm.GetNodeThroughput(nodeID)
	logger.Infof("发送吞吐量: %.2f B/s", sendThroughput)
	logger.Infof("接收吞吐量: %.2f B/s", recvThroughput)

	errorRate := sm.GetNodeErrorRate(nodeID)
	logger.Infof("错误率: %.2f%%", errorRate)
	logger.Info("====================================")
}
