# Telnet Delay Test General

这是一个用于测试Telnet连接延迟的命令行工具，支持单个主机名/IP地址、IPv4网段和IPv6网段的随机IP生成和测试。测试结果将保存到 `rtts.csv` 文件中。

## 功能

- 测试指定主机和端口的TCP连接延迟。
- 支持IPv4和IPv6地址。
- 支持通过命令行参数或交互式输入指定主机、端口和生成IP的数量。
- 能够解析IPv4 CIDR（例如 `192.168.1.0/24`）和IPv6 CIDR（例如 `2400:cb00:2049::/48`）并生成随机IP进行测试。
- 将测试结果（包括IP、格式化IP、格式化IP+端口和延迟）保存到 `rtts.csv` 文件中。

## 编译

确保您的系统已安装GCC编译器。在Windows上，您可能需要MinGW或Cygwin。

在项目根目录下运行 `make` 命令进行编译：

```bash
make
```

这将会在 `build/bin/` 目录下生成可执行文件 `telnet_delay_test_general` (Linux/macOS) 或 `telnet_delay_test_general.exe` (Windows)。

## 使用方法

### 运行可执行文件

```bash
./build/bin/telnet_delay_test_general
```

或者在Windows上：

```bash
.\build\bin\telnet_delay_test_general.exe
```

### 命令行参数

您可以通过命令行参数指定主机、端口和生成IP的数量：

```bash
./build/bin/telnet_delay_test_general <主机名/IP/网段> [端口] [生成IP数量]
```

**示例：**

1. **测试单个主机名或IP地址 (默认端口 443)：**
   ```bash
   ./build/bin/telnet_delay_test_general example.com
   ```

2. **测试单个主机名或IP地址 (指定端口 8080)：**
   ```bash
   ./build/bin/telnet_delay_test_general 192.168.1.1 8080
   ```

3. **测试IPv4网段并生成10个随机IP (默认端口 443)：**
   ```bash
   ./build/bin/telnet_delay_test_general 192.168.1.0/24 443 10
   ```

4. **测试IPv6网段并生成5个随机IP (指定端口 22)：**
   ```bash
   ./build/bin/telnet_delay_test_general 2400:cb00:2049::/48 22 5
   ```

### 交互式输入

如果您不提供命令行参数，程序将提示您输入主机名/IP/网段、端口和生成IP的数量。

## 输出文件

程序运行后，会在当前目录下生成一个名为 `rtts.csv` 的CSV文件，其中包含以下列：

- `ip`: 原始IP地址或主机名。
- `ip_with_brackets`: 格式化后的IP地址（IPv6地址会用方括号括起来）。
- `ip_port_with_brackets`: 格式化后的IP地址和端口（IPv6地址会用方括号括起来）。
- `延迟`: 连接延迟（毫秒）或错误信息。

## 清理

要清理编译生成的文件和目录，运行：

```bash
make clean
```

这将删除 `build` 目录及其内容，包括可执行文件和中间对象文件。