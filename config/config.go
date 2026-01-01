package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type ServerConfig struct {
	ListenAddr    string `json:"listen_addr"`
	ServerSecret  string `json:"server_secret"`
	EnableStats   bool   `json:"enable_stats"`
	MaxConnections int   `json:"max_connections"`
	LogLevel      string `json:"log_level"`
	LogPath       string `json:"log_path"`
}

type ClientConfig struct {
	ServerAddr    string `json:"server_addr"`
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name"`
	AuthToken     string `json:"auth_token"`
	TUNName       string `json:"tun_name"`
	TUNIP         string `json:"tun_ip"`
	TUNSubnet     string `json:"tun_subnet"`
	EnableStats   bool   `json:"enable_stats"`
	AutoReconnect bool   `json:"auto_reconnect"`
	LogLevel      string `json:"log_level"`
	LogPath       string `json:"log_path"`
}

type Config struct {
	Server *ServerConfig `json:"server,omitempty"`
	Client *ClientConfig `json:"client,omitempty"`
}

var (
	ErrConfigNotFound = errors.New("配置文件未找到")
	ErrInvalidConfig   = errors.New("无效的配置")
)

func LoadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = "config/config.json"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func validateConfig(config *Config) error {
	if config.Server != nil {
		if config.Server.ListenAddr == "" {
			config.Server.ListenAddr = ":8080"
		}
		if config.Server.ServerSecret == "" {
			config.Server.ServerSecret = "default-secret-change-me"
		}
		if config.Server.MaxConnections == 0 {
			config.Server.MaxConnections = 100
		}
		if config.Server.LogLevel == "" {
			config.Server.LogLevel = "INFO"
		}
		if config.Server.LogPath == "" {
			config.Server.LogPath = "logs"
		}
	}

	if config.Client != nil {
		if config.Client.ServerAddr == "" {
			return errors.New("客户端配置必须指定服务器地址")
		}
		if config.Client.LogLevel == "" {
			config.Client.LogLevel = "INFO"
		}
		if config.Client.LogPath == "" {
			config.Client.LogPath = "logs"
		}
	}

	return nil
}

func SaveConfig(config *Config, configPath string) error {
	if config == nil {
		return ErrInvalidConfig
	}

	if configPath == "" {
		configPath = "config/config.json"
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	return nil
}

func CreateDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:    ":8080",
		ServerSecret:  "change-this-secret-in-production",
		EnableStats:   true,
		MaxConnections: 100,
		LogLevel:      "INFO",
		LogPath:       "logs",
	}
}

func CreateDefaultClientConfig(serverAddr string) *ClientConfig {
	return &ClientConfig{
		ServerAddr:    serverAddr,
		NodeID:        "",
		NodeName:      "",
		AuthToken:     "",
		TUNName:       "vlan0",
		TUNIP:         "10.0.0.2",
		TUNSubnet:     "255.255.255.0",
		EnableStats:   true,
		AutoReconnect: true,
		LogLevel:      "INFO",
		LogPath:       "logs",
	}
}

func CreateDefaultConfig() *Config {
	return &Config{
		Server: CreateDefaultServerConfig(),
		Client: nil,
	}
}

func ParseLogLevel(level string) int {
	switch level {
	case "DEBUG":
		return 0
	case "INFO":
		return 1
	case "WARN":
		return 2
	case "ERROR":
		return 3
	default:
		return 1
	}
}
