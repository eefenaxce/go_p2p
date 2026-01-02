package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eefenaxce/vlan-tool/internal/logger"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	DefaultMTU = 1300 // 减小MTU，为JSON序列化和协议头留出空间
	BufferSize = 4096
	MaxRetries = 3
	RetryDelay = 2 * time.Second
)

type TUNDevice struct {
	name       string
	fd         *os.File
	tunDev     tun.Device
	mtu        int
	ipAddress  net.IP
	subnetMask net.IPMask
	isUp       bool
	mu         sync.RWMutex
	readChan   chan []byte
	writeChan  chan []byte
	stopChan   chan struct{}
}

type TUNConfig struct {
	Name       string
	MTU        int
	IPAddress  string
	SubnetMask string
}

var (
	ErrDeviceNotFound = errors.New("虚拟网卡设备未找到")
	ErrDeviceBusy     = errors.New("虚拟网卡设备忙")
	ErrInvalidConfig  = errors.New("无效的配置")
)

func NewTUNDevice(config *TUNConfig) (*TUNDevice, error) {
	if config.Name == "" {
		return nil, ErrInvalidConfig
	}

	if config.MTU == 0 {
		config.MTU = DefaultMTU
	}

	ip := net.ParseIP(config.IPAddress)
	if ip == nil {
		return nil, fmt.Errorf("无效的IP地址: %s", config.IPAddress)
	}

	// 转换子网掩码为CIDR格式
	var subnet *net.IPNet
	var err error

	if strings.Contains(config.SubnetMask, ".") {
		// 传统子网掩码格式 (如 255.255.255.0)
		mask := net.ParseIP(config.SubnetMask)
		if mask == nil {
			return nil, fmt.Errorf("无效的传统子网掩码: %s", config.SubnetMask)
		}

		// 将IP转换为IPMask
		ipMask := net.IPv4Mask(mask[12], mask[13], mask[14], mask[15])
		_, bits := ipMask.Size()
		if bits == 0 {
			return nil, fmt.Errorf("无效的传统子网掩码: %s", config.SubnetMask)
		}

		subnet = &net.IPNet{
			IP:   ip,
			Mask: ipMask,
		}
	} else {
		// CIDR格式 (如 24)
		_, subnet, err = net.ParseCIDR(config.IPAddress + "/" + config.SubnetMask)
		if err != nil {
			return nil, fmt.Errorf("无效的CIDR子网掩码: %s", config.SubnetMask)
		}
	}

	return &TUNDevice{
		name:       config.Name,
		mtu:        config.MTU,
		ipAddress:  ip,
		subnetMask: subnet.Mask,
		readChan:   make(chan []byte, BufferSize),
		writeChan:  make(chan []byte, BufferSize),
		stopChan:   make(chan struct{}),
	}, nil
}

func (t *TUNDevice) Create() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isUp {
		return fmt.Errorf("设备已启动: %s", t.name)
	}

	logger.Infof("正在创建虚拟网卡: %s", t.name)

	switch runtime.GOOS {
	case "windows":
		return t.createWindows()
	case "darwin":
		return t.createDarwin()
	case "linux":
		return t.createLinux()
	default:
		return fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}
}

func (t *TUNDevice) createWindows() error {
	logger.Info("Windows平台虚拟网卡创建: 使用WinTun驱动")
	return createWindowsTUN(t)
}

func (t *TUNDevice) createDarwin() error {
	logger.Info("macOS平台虚拟网卡创建: 使用utun设备")
	return createDarwinTUN(t)
}

func (t *TUNDevice) createLinux() error {
	logger.Info("Linux平台虚拟网卡创建: 使用tun设备")
	return createLinuxTUN(t)
}

func (t *TUNDevice) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.isUp {
		return fmt.Errorf("设备未启动: %s", t.name)
	}

	logger.Infof("正在启动TUN设备读取循环: %s", t.name)

	go t.readLoop()

	return nil
}

func (t *TUNDevice) readLoop() {
	logger.Infof("TUN设备读取循环已启动: %s", t.name)
	defer logger.Infof("TUN设备读取循环已停止: %s", t.name)

	for {
		select {
		case <-t.stopChan:
			return
		default:
			var n int
			var err error
			var buffer []byte

			if t.tunDev != nil {
				batchSize := t.tunDev.BatchSize()
				bufs := make([][]byte, batchSize)
				sizes := make([]int, batchSize)
				for i := range bufs {
					bufs[i] = make([]byte, t.mtu)
				}

				n, err = t.tunDev.Read(bufs, sizes, 0)
				if err == nil && n > 0 {
					for i := 0; i < n; i++ {
						if sizes[i] > 0 {
							data := make([]byte, sizes[i])
							copy(data, bufs[i][:sizes[i]])
							select {
							case t.readChan <- data:
							default:
								logger.Warnf("读取通道已满，丢弃数据包")
							}
						}
					}
					continue
				}
			} else if t.fd != nil {
				buffer = make([]byte, t.mtu+4)
				n, err = t.fd.Read(buffer)
				if err == nil && n > 0 {
					data := make([]byte, n)
					copy(data, buffer[:n])
					select {
					case t.readChan <- data:
					default:
						logger.Warnf("读取通道已满，丢弃数据包")
					}
					continue
				}
			} else {
				logger.Warnf("TUN设备未初始化，无法读取数据")
				time.Sleep(time.Second)
				continue
			}

			if err != nil {
				if !t.isUp {
					return
				}
				logger.Errorf("读取TUN设备失败: %v", err)
				time.Sleep(time.Second)
			}
		}
	}
}

func (t *TUNDevice) GetReadChannel() <-chan []byte {
	return t.readChan
}

func (t *TUNDevice) GetWriteChannel() chan<- []byte {
	return t.writeChan
}

func (t *TUNDevice) subnetMaskToCIDR(mask net.IPMask) string {
	ones, _ := mask.Size()
	return strconv.Itoa(ones)
}

func (t *TUNDevice) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.isUp {
		return nil
	}

	logger.Infof("正在关闭虚拟网卡: %s", t.name)

	close(t.stopChan)

	switch runtime.GOOS {
	case "windows":
		return t.closeWindows()
	case "darwin":
		return t.closeDarwin()
	case "linux":
		return t.closeLinux()
	default:
		return fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}
}

func (t *TUNDevice) closeWindows() error {
	logger.Infof("关闭Windows TUN设备: %s", t.name)
	if t.tunDev != nil {
		return t.tunDev.Close()
	}
	if t.fd != nil {
		return t.fd.Close()
	}
	return nil
}

func (t *TUNDevice) closeDarwin() error {
	logger.Infof("关闭macOS TUN设备: %s", t.name)
	if t.fd != nil {
		return t.fd.Close()
	}
	return nil
}

func (t *TUNDevice) closeLinux() error {
	logger.Infof("关闭Linux TUN设备: %s", t.name)
	if t.fd != nil {
		return t.fd.Close()
	}
	return nil
}

func (t *TUNDevice) Read() ([]byte, error) {
	if !t.isUp {
		return nil, fmt.Errorf("设备未启动: %s", t.name)
	}

	if t.fd == nil {
		return nil, fmt.Errorf("文件描述符为空")
	}

	buffer := make([]byte, t.mtu+4)
	n, err := t.fd.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取TUN设备失败: %w", err)
	}

	return buffer[:n], nil
}

func (t *TUNDevice) Write(data []byte) error {
	if !t.isUp {
		return fmt.Errorf("设备未启动: %s", t.name)
	}

	if t.tunDev != nil {
		bufs := [][]byte{data}
		_, err := t.tunDev.Write(bufs, 0)
		if err != nil {
			return fmt.Errorf("写入TUN设备失败: %w", err)
		}
		return nil
	}

	if t.fd == nil {
		return fmt.Errorf("文件描述符为空")
	}

	if _, err := t.fd.Write(data); err != nil {
		return fmt.Errorf("写入TUN设备失败: %w", err)
	}

	return nil
}

func (t *TUNDevice) GetName() string {
	return t.name
}

func (t *TUNDevice) GetIPAddress() net.IP {
	return t.ipAddress
}

func (t *TUNDevice) GetSubnetMask() net.IPMask {
	return t.subnetMask
}

func (t *TUNDevice) GetMTU() int {
	return t.mtu
}

func (t *TUNDevice) IsUp() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.isUp
}

func ListTUNDevices() ([]string, error) {
	switch runtime.GOOS {
	case "windows":
		return listWindowsTUNDevices()
	case "darwin":
		return listDarwinTUNDevices()
	case "linux":
		return listLinuxTUNDevices()
	default:
		return nil, fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}
}

func DeleteTUNDevice(name string) error {
	logger.Infof("删除TUN设备: %s", name)

	switch runtime.GOOS {
	case "windows":
		return deleteWindowsTUNDevice(name)
	case "darwin":
		return deleteDarwinTUNDevice(name)
	case "linux":
		return deleteLinuxTUNDevice(name)
	default:
		return fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}
}
