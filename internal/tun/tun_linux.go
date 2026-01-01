//go:build linux
// +build linux

package tun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/eefenaxce/vlan-tool/internal/logger"
)

func createLinuxTUN(t *TUNDevice) error {
	logger.Info("正在初始化Linux tun设备")

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("打开/dev/net/tun失败: %w", err)
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [20]byte
	}

	copy(ifr.name[:], t.name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)

	if errno != 0 {
		unix.Close(fd)
		return fmt.Errorf("配置TUN设备失败: %v", errno)
	}

	t.fd = os.NewFile(uintptr(fd), "/dev/net/tun")

	if err := t.configureLinuxInterface(); err != nil {
		t.fd.Close()
		return fmt.Errorf("配置网络接口失败: %w", err)
	}

	return nil
}

func (t *TUNDevice) configureLinuxInterface() error {
	ifName := t.name

	if err := exec.Command("ip", "addr", "add", t.ipAddress.String()+"/"+t.subnetMaskToCIDR(t.subnetMask), "dev", ifName).Run(); err != nil {
		return fmt.Errorf("设置IP地址失败: %w", err)
	}

	if err := exec.Command("ip", "link", "set", "dev", ifName, "up").Run(); err != nil {
		return fmt.Errorf("启用接口失败: %w", err)
	}

	if err := exec.Command("ip", "link", "set", "dev", ifName, "mtu", strconv.Itoa(t.mtu)).Run(); err != nil {
		return fmt.Errorf("设置MTU失败: %w", err)
	}

	return nil
}

func listLinuxTUNDevices() ([]string, error) {
	logger.Info("列出Linux TUN设备")

	output, err := exec.Command("ip", "link", "show", "type", "tun").CombinedOutput()
	if err != nil {
		return []string{}, nil
	}

	lines := strings.Split(string(output), "\n")
	devices := []string{}

	for _, line := range lines {
		if strings.Contains(line, "tun") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				name := strings.TrimSuffix(fields[1], ":")
				if strings.HasPrefix(name, "tun") {
					devices = append(devices, name)
				}
			}
		}
	}

	return devices, nil
}

func deleteLinuxTUNDevice(name string) error {
	logger.Infof("删除Linux TUN设备: %s", name)

	if err := exec.Command("ip", "link", "set", name, "down").Run(); err != nil {
		return fmt.Errorf("禁用接口失败: %w", err)
	}

	if err := exec.Command("ip", "tuntap", "del", "dev", name, "mode", "tun").Run(); err != nil {
		return fmt.Errorf("删除TUN设备失败: %w", err)
	}

	logger.Infof("Linux TUN设备已删除: %s", name)
	return nil
}

func createWindowsTUN(t *TUNDevice) error {
	return errors.New("Linux平台不支持创建Windows TUN设备")
}

func createDarwinTUN(t *TUNDevice) error {
	return errors.New("Linux平台不支持创建Darwin TUN设备")
}

func deleteWindowsTUNDevice(name string) error {
	return errors.New("Linux平台不支持删除Windows TUN设备")
}

func deleteDarwinTUNDevice(name string) error {
	return errors.New("Linux平台不支持删除Darwin TUN设备")
}

func listWindowsTUNDevices() ([]string, error) {
	return []string{}, errors.New("Linux平台不支持列出Windows TUN设备")
}

func listDarwinTUNDevices() ([]string, error) {
	return []string{}, errors.New("Linux平台不支持列出Darwin TUN设备")
}
