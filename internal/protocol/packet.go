package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	ProtocolVersion = 1
	MaxPacketSize   = 3000 // 增加最大数据包大小，考虑JSON序列化和Base64编码的开销
	HeaderSize      = 20
)

const (
	PacketTypeAuth      = 0x01
	PacketTypeData      = 0x02
	PacketTypeControl   = 0x03
	PacketTypeDiscovery = 0x04
	PacketTypePing      = 0x05
	PacketTypePong      = 0x06
	PacketTypeStats     = 0x07
)

const (
	ControlTypeRegister = 0x01
	ControlTypeUnregister = 0x02
	ControlTypeHeartbeat = 0x03
	ControlTypeError = 0x04
)

type PacketHeader struct {
	Version    uint8
	Type       uint8
	Control    uint8
	Flags      uint8
	Length     uint16
	Sequence   uint32
	SessionID  uint32
	Checksum   uint16
}

type AuthRequest struct {
	NodeID     string `json:"node_id"`
	AuthToken  string `json:"auth_token"`
	IPAddress  string `json:"ip_address"`
	MacAddress string `json:"mac_address"`
	Version    string `json:"version"`
}

type AuthResponse struct {
	Success    bool   `json:"success"`
	NodeID     string `json:"node_id"`
	SessionID  uint32 `json:"session_id"`
	IPAddress  string `json:"ip_address"`
	SubnetMask string `json:"subnet_mask"`
	Gateway    string `json:"gateway"`
	Message    string `json:"message"`
}

type DataPacket struct {
	SourceNodeID string `json:"source_node_id"`
	DestNodeID   string `json:"dest_node_id"`
	Data         []byte `json:"data"`
}

type ControlPacket struct {
	ControlType uint8                 `json:"control_type"`
	NodeID      string                `json:"node_id"`
	Data        map[string]interface{} `json:"data"`
}

type DiscoveryPacket struct {
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name"`
	IPAddress  string `json:"ip_address"`
	Port       int    `json:"port"`
	Version    string `json:"version"`
	Timestamp  int64  `json:"timestamp"`
}

type PingPacket struct {
	Sequence   uint32 `json:"sequence"`
	Timestamp  int64  `json:"timestamp"`
	NodeID     string `json:"node_id"`
}

type PongPacket struct {
	Sequence   uint32 `json:"sequence"`
	Timestamp  int64  `json:"timestamp"`
	NodeID     string `json:"node_id"`
	RTT        int64  `json:"rtt"`
}

type StatsPacket struct {
	NodeID        string `json:"node_id"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
	Errors        uint64 `json:"errors"`
	Uptime        int64  `json:"uptime"`
}

type Packet struct {
	Header PacketHeader
	Body   []byte
}

func NewPacket(packetType uint8, body []byte) *Packet {
	return &Packet{
		Header: PacketHeader{
			Version:  ProtocolVersion,
			Type:     packetType,
			Length:   uint16(len(body)),
			Sequence: 0,
		},
		Body: body,
	}
}

func (p *Packet) Serialize() ([]byte, error) {
	if len(p.Body) > MaxPacketSize-HeaderSize {
		return nil, errors.New("数据包大小超过限制")
	}

	buf := make([]byte, HeaderSize+len(p.Body))

	buf[0] = p.Header.Version
	buf[1] = p.Header.Type
	buf[2] = p.Header.Control
	buf[3] = p.Header.Flags

	binary.BigEndian.PutUint16(buf[4:6], p.Header.Length)
	binary.BigEndian.PutUint32(buf[6:10], p.Header.Sequence)
	binary.BigEndian.PutUint32(buf[10:14], p.Header.SessionID)

	checksum := p.calculateChecksum()
	binary.BigEndian.PutUint16(buf[14:16], checksum)

	copy(buf[HeaderSize:], p.Body)

	return buf, nil
}

func (p *Packet) calculateChecksum() uint16 {
	checksum := uint16(0)

	checksum ^= uint16(p.Header.Version) << 8
	checksum ^= uint16(p.Header.Type)
	checksum ^= uint16(p.Header.Control) << 8
	checksum ^= uint16(p.Header.Flags)

	checksum ^= p.Header.Length
	checksum ^= uint16(p.Header.Sequence & 0xFFFF)
	checksum ^= uint16(p.Header.Sequence >> 16)
	checksum ^= uint16(p.Header.SessionID & 0xFFFF)
	checksum ^= uint16(p.Header.SessionID >> 16)

	for i := 0; i < len(p.Body); i += 2 {
		if i+1 < len(p.Body) {
			checksum ^= uint16(p.Body[i]) << 8
			checksum ^= uint16(p.Body[i+1])
		} else {
			checksum ^= uint16(p.Body[i]) << 8
		}
	}

	return checksum
}

func DeserializePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("数据包太小，无法解析")
	}

	p := &Packet{}

	p.Header.Version = data[0]
	p.Header.Type = data[1]
	p.Header.Control = data[2]
	p.Header.Flags = data[3]

	p.Header.Length = binary.BigEndian.Uint16(data[4:6])
	p.Header.Sequence = binary.BigEndian.Uint32(data[6:10])
	p.Header.SessionID = binary.BigEndian.Uint32(data[10:14])
	p.Header.Checksum = binary.BigEndian.Uint16(data[14:16])

	if p.Header.Version != ProtocolVersion {
		return nil, fmt.Errorf("不支持的协议版本: %d", p.Header.Version)
	}

	expectedLength := int(p.Header.Length)
	if len(data) < HeaderSize+expectedLength {
		return nil, errors.New("数据包长度不匹配")
	}

	p.Body = data[HeaderSize : HeaderSize+expectedLength]

	return p, nil
}

func (p *Packet) Validate() bool {
	return p.calculateChecksum() == p.Header.Checksum
}

func SerializeAuthRequest(req AuthRequest) ([]byte, error) {
	return json.Marshal(req)
}

func DeserializeAuthRequest(data []byte) (AuthRequest, error) {
	var req AuthRequest
	err := json.Unmarshal(data, &req)
	return req, err
}

func SerializeAuthResponse(resp AuthResponse) ([]byte, error) {
	return json.Marshal(resp)
}

func DeserializeAuthResponse(data []byte) (AuthResponse, error) {
	var resp AuthResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}

func SerializeDataPacket(pkt DataPacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DeserializeDataPacket(data []byte) (DataPacket, error) {
	var pkt DataPacket
	err := json.Unmarshal(data, &pkt)
	return pkt, err
}

func SerializeControlPacket(pkt ControlPacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DeserializeControlPacket(data []byte) (ControlPacket, error) {
	var pkt ControlPacket
	err := json.Unmarshal(data, &pkt)
	return pkt, err
}

func SerializeDiscoveryPacket(pkt DiscoveryPacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DeserializeDiscoveryPacket(data []byte) (DiscoveryPacket, error) {
	var pkt DiscoveryPacket
	err := json.Unmarshal(data, &pkt)
	return pkt, err
}

func SerializePingPacket(pkt PingPacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DeserializePingPacket(data []byte) (PingPacket, error) {
	var pkt PingPacket
	err := json.Unmarshal(data, &pkt)
	return pkt, err
}

func SerializePongPacket(pkt PongPacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DeserializePongPacket(data []byte) (PongPacket, error) {
	var pkt PongPacket
	err := json.Unmarshal(data, &pkt)
	return pkt, err
}

func SerializeStatsPacket(pkt StatsPacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DeserializeStatsPacket(data []byte) (StatsPacket, error) {
	var pkt StatsPacket
	err := json.Unmarshal(data, &pkt)
	return pkt, err
}
