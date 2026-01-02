//go:build windows
// +build windows

package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/eefenaxce/vlan-tool/internal/logger"
)

var (
	wintunDLLPath string
)

func init() {
	exePath, err := os.Executable()
	if err != nil {
		logger.Warnf("获取可执行文件路径失败: %v", err)
		return
	}

	wintunDLLPath = filepath.Join(filepath.Dir(exePath), "wintun.dll")
}

func createWindowsTUN(t *TUNDevice) error {
	logger.Info("正在初始化Windows TUN设备，使用WinTun驱动")

	tapName := t.name

	logger.Infof("创建WinTun设备: %s", tapName)

	tunDevice, err := tun.CreateTUN(tapName, t.mtu)
	if err != nil {
		return fmt.Errorf("创建WinTun设备失败: %w", err)
	}

	t.tunDev = tunDevice

	logger.Infof("WinTun设备已创建: %s", tapName)

	ipAddr := t.ipAddress.String()
	ones, _ := t.subnetMask.Size()
	cidr := fmt.Sprintf("%s/%d", ipAddr, ones)

	logger.Infof("配置IP地址: %s", cidr)

	err = configureIPAddressWithNetsh(tapName, cidr)
	if err != nil {
		return fmt.Errorf("配置IP地址失败: %w", err)
	}

	logger.Infof("IP地址配置成功: %s", cidr)

	t.isUp = true
	logger.Infof("Windows TUN设备初始化完成: %s, MTU: %d", tapName, t.mtu)

	return nil
}

func configureIPAddressWithNetsh(interfaceName string, cidr string) error {
	// 将CIDR格式转换为IP地址、子网掩码
	ipAddr, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("无效的CIDR格式: %w", err)
	}

	// 确保只处理IPv4地址
	ipAddrV4 := ipAddr.To4()
	if ipAddrV4 == nil {
		return fmt.Errorf("仅支持IPv4地址，当前地址: %s", ipAddr.String())
	}

	// 将IP地址转换为字符串
	ipStr := ipAddrV4.String()
	// 将子网掩码转换为字符串
	maskStr := net.IP(ipNet.Mask).String()
	// 使用固定网关地址10.0.0.1，这是一个通用的网关地址
	gatewayStr := "10.0.0.1"

	// 构造netsh命令，使用单行格式避免换行问题
	cmdArgs := []string{
		"interface", "ip", "set", "address",
		fmt.Sprintf("name=\"%s\"", interfaceName),
		"static", ipStr, maskStr, gatewayStr, "1",
	}

	logger.Infof("执行netsh命令: netsh %s", strings.Join(cmdArgs, " "))
	cmd := exec.Command("netsh", cmdArgs...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh命令执行失败: %w, 输出: %s", err, string(output))
	}

	logger.Infof("netsh命令执行成功: %s", string(output))
	return nil
}

func listWindowsTUNDevices() ([]string, error) {
	logger.Info("列出Windows TUN设备")

	cmd := exec.Command("netsh", "interface", "show", "interface")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warnf("查询网络接口失败: %v", err)
		return []string{}, nil
	}

	lines := strings.Split(string(output), "\n")
	devices := []string{}

	for _, line := range lines {
		if strings.Contains(line, "Wintun") || strings.Contains(line, "WireGuard") {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				devices = append(devices, fields[3])
			}
		}
	}

	logger.Infof("找到 %d 个WinTun设备", len(devices))
	return devices, nil
}

func deleteWindowsTUNDevice(name string) error {
	logger.Infof("Windows平台不支持删除TUN设备: %s (设备将保持持久化)", name)
	return errors.New("Windows平台不支持删除TUN设备，设备将保持持久化状态")
}

func createDarwinTUN(t *TUNDevice) error {
	return errors.New("Windows平台不支持创建Darwin TUN设备")
}

func createLinuxTUN(t *TUNDevice) error {
	return errors.New("Windows平台不支持创建Linux TUN设备")
}

func deleteDarwinTUNDevice(name string) error {
	return errors.New("Windows平台不支持删除Darwin TUN设备")
}

func deleteLinuxTUNDevice(name string) error {
	return errors.New("Windows平台不支持删除Linux TUN设备")
}

func listDarwinTUNDevices() ([]string, error) {
	return []string{}, errors.New("Windows平台不支持列出Darwin TUN设备")
}

func listLinuxTUNDevices() ([]string, error) {
	return []string{}, errors.New("Windows平台不支持列出Linux TUN设备")
}
