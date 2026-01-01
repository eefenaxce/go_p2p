//go:build windows
// +build windows

package tun

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/eefenaxce/vlan-tool/internal/logger"
)

func createWindowsTUN(t *TUNDevice) error {
	logger.Info("正在初始化Windows TUN设备")

	tapName := t.name

	cmd := exec.Command("netsh", "interface", "ip", "show", "interface")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warnf("查询网络接口失败: %v", err)
	}

	if !strings.Contains(string(output), tapName) {
		logger.Warnf("未找到TAP设备: %s，请确保已安装TAP-Windows驱动", tapName)
		return errors.New("TAP设备未找到，请安装TAP-Windows驱动")
	}

	cidr := t.ipAddress.String() + "/" + t.subnetMaskToCIDR(t.subnetMask)
	cmd = exec.Command("netsh", "interface", "ip", "set", "address", "name="+tapName, "static", cidr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("设置IP地址失败: %w", err)
	}

	cmd = exec.Command("netsh", "interface", "set", "interface", tapName, "enabled")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("启用接口失败: %w", err)
	}

	logger.Infof("Windows TUN设备配置完成: %s", tapName)
	t.isUp = true
	t.fd = nil

	return nil
}

func listWindowsTUNDevices() ([]string, error) {
	logger.Info("列出Windows TUN设备")

	output, err := exec.Command("netsh", "interface", "show", "interface").CombinedOutput()
	if err != nil {
		return []string{}, nil
	}

	lines := strings.Split(string(output), "\n")
	devices := []string{}

	for _, line := range lines {
		if strings.Contains(line, "TAP") || strings.Contains(line, "Wintun") {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				devices = append(devices, fields[3])
			}
		}
	}

	return devices, nil
}

func deleteWindowsTUNDevice(name string) error {
	logger.Infof("删除Windows TUN设备: %s", name)

	if err := exec.Command("netsh", "interface", "set", "interface", name, "disabled").Run(); err != nil {
		return fmt.Errorf("禁用接口失败: %w", err)
	}

	logger.Infof("Windows TUN设备已禁用: %s", name)
	return nil
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
