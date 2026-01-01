//go:build darwin
// +build darwin

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

func createDarwinTUN(t *TUNDevice) error {
	logger.Info("正在初始化macOS utun设备")

	for i := 0; i < 10; i++ {
		ifName := fmt.Sprintf("utun%d", i)
		fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
		if err != nil {
			return fmt.Errorf("创建socket失败: %w", err)
		}

		var ctlInfo struct {
			id   uint32
			name [16]byte
		}

		copy(ctlInfo.name[:], "com.apple.net.utun_control")

		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			uintptr(2),
			uintptr(unsafe.Pointer(&ctlInfo)),
		)

		if errno != 0 {
			unix.Close(fd)
			continue
		}

		var ifr struct {
			name   [16]byte
			family uint32
			unit   uint32
			flags  uint32
		}

		ifr.family = unix.AF_SYSTEM
		ifr.unit = uint32(i)

		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			uintptr(0x80000004|0x40000000|0x00000002),
			uintptr(unsafe.Pointer(&ifr)),
		)

		if errno != 0 {
			unix.Close(fd)
			continue
		}

		t.name = ifName
		t.fd = os.NewFile(uintptr(fd), ifName)

		if err := t.configureDarwinInterface(); err != nil {
			t.fd.Close()
			return fmt.Errorf("配置网络接口失败: %w", err)
		}

		return nil
	}

	return errors.New("无法创建utun设备")
}

func (t *TUNDevice) configureDarwinInterface() error {
	ifName := t.name

	if err := exec.Command("ifconfig", ifName, "inet", t.ipAddress.String(), t.subnetMask.String(), "up").Run(); err != nil {
		return fmt.Errorf("设置IP地址失败: %w", err)
	}

	if err := exec.Command("ifconfig", ifName, "mtu", strconv.Itoa(t.mtu)).Run(); err != nil {
		return fmt.Errorf("设置MTU失败: %w", err)
	}

	return nil
}

func listDarwinTUNDevices() ([]string, error) {
	logger.Info("列出macOS TUN设备")

	output, err := exec.Command("ifconfig", "-a").CombinedOutput()
	if err != nil {
		return []string{}, nil
	}

	lines := strings.Split(string(output), "\n")
	devices := []string{}

	for _, line := range lines {
		if strings.Contains(line, "utun") && strings.Contains(line, "flags=") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				name := strings.TrimSuffix(fields[0], ":")
				if strings.HasPrefix(name, "utun") {
					devices = append(devices, name)
				}
			}
		}
	}

	return devices, nil
}

func deleteDarwinTUNDevice(name string) error {
	logger.Infof("删除macOS TUN设备: %s", name)

	if err := exec.Command("ifconfig", name, "down").Run(); err != nil {
		return fmt.Errorf("禁用接口失败: %w", err)
	}

	logger.Infof("macOS TUN设备已删除: %s", name)
	return nil
}

func createWindowsTUN(t *TUNDevice) error {
	return errors.New("Darwin平台不支持创建Windows TUN设备")
}

func createLinuxTUN(t *TUNDevice) error {
	return errors.New("Darwin平台不支持创建Linux TUN设备")
}

func deleteWindowsTUNDevice(name string) error {
	return errors.New("Darwin平台不支持删除Windows TUN设备")
}

func deleteLinuxTUNDevice(name string) error {
	return errors.New("Darwin平台不支持删除Linux TUN设备")
}

func listWindowsTUNDevices() ([]string, error) {
	return []string{}, errors.New("Darwin平台不支持列出Windows TUN设备")
}

func listLinuxTUNDevices() ([]string, error) {
	return []string{}, errors.New("Darwin平台不支持列出Linux TUN设备")
}
