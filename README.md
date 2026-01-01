# VLAN 工具

一个功能完整的跨平台虚拟局域网(VLAN)工具，支持Windows、macOS和Linux三个主流操作系统平台。

## 功能特性

### 核心功能
- ✅ 自动创建并配置虚拟网卡
- ✅ 跨平台支持（Windows/macOS/Linux）
- ✅ 服务端节点管理和连接认证
- ✅ 客户端多用户同时连接
- ✅ 节点间透明通信
- ✅ 高效的数据包转发机制
- ✅ 安全的节点认证机制

### 日志系统
- ✅ 完整的中文日志输出
- ✅ 时间戳、日志级别（INFO/WARN/ERROR/DEBUG）
- ✅ 模块名称和具体信息
- ✅ 日志分级输出
- ✅ 日志文件轮转功能

### 附加功能
- ✅ 节点自动发现
- ✅ 网络流量统计
- ✅ 连接状态实时显示
- ✅ 自动重连机制
- ✅ 心跳保活机制

## 项目结构

```
go_p2p/
├── cmd/
│   ├── server/          # 服务端主程序
│   └── client/          # 客户端主程序
├── internal/
│   ├── auth/            # 认证模块
│   ├── client/          # 客户端实现
│   ├── discovery/       # 节点发现
│   ├── logger/          # 日志系统
│   ├── protocol/        # 协议定义
│   ├── server/          # 服务端实现
│   ├── stats/           # 统计模块
│   └── tun/             # 虚拟网卡管理
├── config/              # 配置文件
│   └── config.json      # 默认配置
├── docs/                # 文档
├── go.mod               # Go模块文件
└── README.md            # 本文件
```

## 快速开始

### 环境要求

- Go 1.25 或更高版本
- Windows/macOS/Linux 操作系统
- 管理员/root权限（用于创建虚拟网卡）

### 安装

1. 克隆或下载项目代码

2. 初始化依赖（如果需要）

```bash
go mod tidy
```

### 编译

#### 编译服务端

```bash
# Windows
go build -o vlan-server.exe ./cmd/server

# Linux/macOS
go build -o vlan-server ./cmd/server
```

#### 编译客户端

```bash
# Windows
go build -o vlan-client.exe ./cmd/client

# Linux/macOS
go build -o vlan-client ./cmd/client
```

#### 跨平台编译

```bash
# Windows 64位
GOOS=windows GOARCH=amd64 go build -o vlan-server.exe ./cmd/server
GOOS=windows GOARCH=amd64 go build -o vlan-client.exe ./cmd/client

# Linux 64位
GOOS=linux GOARCH=amd64 go build -o vlan-server ./cmd/server
GOOS=linux GOARCH=amd64 go build -o vlan-client ./cmd/client

# macOS 64位
GOOS=darwin GOARCH=amd64 go build -o vlan-server ./cmd/server
GOOS=darwin GOARCH=amd64 go build -o vlan-client ./cmd/client
```

## 使用说明

### 配置文件

编辑 `config/config.json` 文件来配置服务器和客户端参数：

```json
{
  "server": {
    "listen_addr": ":8080",
    "server_secret": "change-this-secret-in-production",
    "enable_stats": true,
    "max_connections": 100,
    "log_level": "INFO",
    "log_path": "logs"
  },
  "client": {
    "server_addr": "localhost:8080",
    "node_id": "",
    "node_name": "",
    "auth_token": "",
    "tun_name": "vlan0",
    "tun_ip": "10.0.0.2",
    "tun_subnet": "255.255.255.0",
    "enable_stats": true,
    "auto_reconnect": true,
    "log_level": "INFO",
    "log_path": "logs"
  }
}
```

### 启动服务端

#### 使用配置文件

```bash
# Windows
vlan-server.exe

# Linux/macOS
./vlan-server
```

#### 使用命令行参数

```bash
# Windows
vlan-server.exe -config config/config.json -log-level DEBUG -log-path logs

# Linux/macOS
./vlan-server -config config/config.json -log-level DEBUG -log-path logs
```

#### 可用参数

- `-config`: 配置文件路径（默认: config/config.json）
- `-log-level`: 日志级别（DEBUG/INFO/WARN/ERROR，默认: INFO）
- `-log-path`: 日志目录路径（默认: logs）

### 启动客户端

#### 使用配置文件

```bash
# Windows
vlan-client.exe

# Linux/macOS
./vlan-client
```

#### 使用命令行参数

```bash
# Windows
vlan-client.exe -server localhost:8080 -node-id mynode -node-name "我的节点" -token mytoken

# Linux/macOS
./vlan-client -server localhost:8080 -node-id mynode -node-name "我的节点" -token mytoken
```

#### 可用参数

- `-config`: 配置文件路径（默认: config/config.json）
- `-server`: 服务器地址（格式: host:port）
- `-node-id`: 节点ID
- `-node-name`: 节点名称
- `-token`: 认证令牌
- `-tun`: 虚拟网卡名称（默认: vlan0）
- `-tun-ip`: 虚拟网卡IP地址（默认: 10.0.0.2）
- `-tun-subnet`: 虚拟网卡子网掩码（默认: 255.255.255.0）
- `-log-level`: 日志级别（DEBUG/INFO/WARN/ERROR，默认: INFO）
- `-log-path`: 日志目录路径（默认: logs）
- `-discovery`: 启用节点发现（默认: false）

## 部署指南

### Windows 部署

1. 以管理员身份运行命令提示符或PowerShell

2. 编译程序：
```bash
go build -o vlan-server.exe ./cmd/server
go build -o vlan-client.exe ./cmd/client
```

3. 启动服务端：
```bash
vlan-server.exe
```

4. 启动客户端（在另一个终端）：
```bash
vlan-client.exe -server localhost:8080 -node-id client1 -node-name "客户端1" -token token1
```

### Linux 部署

1. 使用root权限或sudo

2. 编译程序：
```bash
go build -o vlan-server ./cmd/server
go build -o vlan-client ./cmd/client
```

3. 启动服务端：
```bash
sudo ./vlan-server
```

4. 启动客户端（在另一个终端）：
```bash
sudo ./vlan-client -server localhost:8080 -node-id client1 -node-name "客户端1" -token token1
```

### macOS 部署

1. 使用root权限或sudo

2. 编译程序：
```bash
go build -o vlan-server ./cmd/server
go build -o vlan-client ./cmd/client
```

3. 启动服务端：
```bash
sudo ./vlan-server
```

4. 启动客户端（在另一个终端）：
```bash
sudo ./vlan-client -server localhost:8080 -node-id client1 -node-name "客户端1" -token token1
```

## 使用示例

### 示例1：基本连接

1. 启动服务端：
```bash
./vlan-server
```

2. 启动客户端1：
```bash
./vlan-client -server localhost:8080 -node-id client1 -token token1
```

3. 启动客户端2：
```bash
./vlan-client -server localhost:8080 -node-id client2 -token token2
```

### 示例2：启用节点发现

```bash
./vlan-client -server localhost:8080 -node-id client1 -token token1 -discovery
```

### 示例3：自定义虚拟网卡

```bash
./vlan-client -server localhost:8080 -node-id client1 -token token1 -tun myvlan -tun-ip 10.0.1.2
```

## 日志说明

### 日志级别

- **DEBUG**: 调试信息，用于开发调试
- **INFO**: 一般信息，记录正常运行状态
- **WARN**: 警告信息，记录潜在问题
- **ERROR**: 错误信息，记录错误和异常

### 日志格式

```
[时间戳] [日志级别] [模块名称] 具体信息
```

示例：
```
[2025-12-31 10:30:45.123] [INFO ] [server] 服务器已启动，监听地址: :8080
[2025-12-31 10:30:46.456] [DEBUG] [server] 收到认证请求: 节点ID=client1, IP=10.0.0.2
[2025-12-31 10:30:46.789] [WARN ] [server] 连接数已达上限 100，拒绝新连接
[2025-12-31 10:30:47.012] [ERROR] [server] 读取数据失败: connection reset by peer
```

### 日志文件

日志文件按模块和时间命名，格式为：
```
{模块}_{时间戳}.log
```

例如：
```
server_2025-12-31_10-30-45.log
client_2025-12-31_10-30-46.log
```

日志文件大小达到100MB时会自动轮转。

## 故障排查

### 常见问题

#### 1. 无法创建虚拟网卡

**问题**: 提示权限不足或设备创建失败

**解决方案**:
- Windows: 以管理员身份运行
- Linux/macOS: 使用sudo运行
- 检查是否安装了必要的驱动（Windows需要WinTun）

#### 2. 连接服务器失败

**问题**: 客户端无法连接到服务器

**解决方案**:
- 检查服务器地址和端口是否正确
- 确认服务器已启动并正在监听
- 检查防火墙设置
- 查看服务器日志确认连接请求

#### 3. 认证失败

**问题**: 提示认证失败或令牌无效

**解决方案**:
- 确认节点已在服务端注册
- 检查认证令牌是否正确
- 查看服务端日志获取详细错误信息
- 检查是否因多次失败导致账户锁定

#### 4. 数据包丢失或延迟高

**问题**: 网络通信不稳定

**解决方案**:
- 检查网络连接质量
- 调整MTU大小
- 查看统计信息了解网络状况
- 检查是否有网络拥塞

### 调试技巧

1. **启用DEBUG日志**:
```bash
./vlan-server -log-level DEBUG
./vlan-client -log-level DEBUG
```

2. **查看统计信息**:
- 服务端和客户端会定期输出网络统计信息
- 包括发送/接收字节数、包数、错误数等

3. **检查连接状态**:
- 查看日志中的连接和断开信息
- 确认心跳是否正常发送

4. **测试网络连通性**:
- 使用ping测试虚拟网络内的节点
- 检查虚拟网卡是否正确配置

## 安全建议

1. **修改默认密钥**: 生产环境中务必修改 `server_secret`
2. **使用强令牌**: 为每个节点使用强认证令牌
3. **限制连接数**: 根据实际需求设置最大连接数
4. **启用防火墙**: 限制访问服务器端口的IP地址
5. **定期更新**: 保持程序更新到最新版本
6. **日志审计**: 定期检查日志文件，发现异常行为

## 性能优化

1. **调整MTU**: 根据网络环境调整MTU大小（默认1500）
2. **连接池**: 合理设置最大连接数
3. **日志级别**: 生产环境使用INFO或WARN级别
4. **统计功能**: 不需要时可禁用统计功能以减少开销

## 技术架构

### 协议设计

- **协议版本**: 1
- **最大包大小**: 1500字节
- **包头大小**: 20字节
- **包类型**: 认证、数据、控制、发现、Ping/Pong、统计

### 认证机制

- 基于令牌的节点认证
- 会话管理（会话超时30分钟）
- 失败次数限制（5次后锁定5分钟）
- 心跳保活（30秒间隔）

### 数据转发

- 服务端作为中心转发节点
- 支持多对多通信
- 高效的数据包处理
- 错误处理和重传机制

## 开发说明

### 代码规范

- 遵循Go语言编码规范
- 使用中文注释
- 完整的错误处理
- 详细的日志记录

### 扩展开发

如需添加新功能，可以参考以下模块：

- `internal/protocol`: 添加新的数据包类型
- `internal/auth`: 扩展认证机制
- `internal/discovery`: 增强节点发现功能
- `internal/stats`: 添加更多统计指标

## 许可证

本项目仅供学习和研究使用。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交Issue
- 发送邮件

## 更新日志

### v1.0.0 (2025-12-31)

- 初始版本发布
- 实现基本的VLAN功能
- 支持Windows/macOS/Linux
- 完整的日志系统
- 节点认证和管理
- 数据转发功能
- 统计和监控功能
- 节点自动发现
