
# Telnet Delay Test General



这是一个用于测试Telnet连接延迟的命令行工具，支持单个主机名/IP地址、IPv4网段和IPv6网段的随机IP生成和测试。测试结果将保存到 `rtts.csv` 文件中。


## windows编译前请先安装MinGW，linux编译前请先安装cmake、make、gcc/g++

## 功能

- 测试指定主机和端口的TCP连接延迟。
- 支持IPv4和IPv6地址。
- 支持通过命令行参数或交互式输入指定主机、端口和生成IP的数量。
- 能够解析IPv4 CIDR（例如 `192.168.1.0/24`）和IPv6 CIDR（例如 `2400:cb00:2049::/48`）并生成随机IP进行测试。
- 将测试结果（包括IP、格式化IP、格式化IP+端口和延迟）保存到 `rtts.csv` 文件中。

## 编译

确保您的系统已安装GCC编译器。在Windows上，您需要MinGW，确保MinGW的bin目录已添加到系统环境变量中，例如 `C:\MinGW\bin`，建议使用msys2。在linux上，您需要安装cmake、make、gcc/g++。

不要在有中文路径下编译

windows直接运行install.ps1即可,linux直接运行install.sh即可

```bash
#windows编译,需要允许运行本地脚本
./install.ps1
```

```bash
#linux编译
./install.sh
```
这将会在 `./` 目录下生成可执行文件 `cidr-ping` (Linux/macOS) 或 `cidr-ping.exe` (Windows)。

## 使用方法

### 运行可执行文件

```bash
./cidr-ping
```


### 命令行参数

您可以通过命令行参数指定主机、端口和生成IP的数量：

```bash
./cidr-ping <主机名/IP/网段> [端口] [生成IP数量]
```

**示例：**

1. **测试单个主机名或IP地址 (默认端口 443)：**
   ```bash
   ./cidr-ping example.com
   ```

2. **测试单个主机名或IP地址 (指定端口 8080)：**
   ```bash
   ./cidr-ping 192.168.1.1 8080
   ```

3. **测试IPv4网段并生成10个随机IP (默认端口 443)：**
   ```bash
   ./cidr-ping 192.168.1.0/24 443 10
   ```

4. **测试IPv6网段并生成5个随机IP (指定端口 22)：**
   ```bash
   ./cidr-ping 2400:cb00:2049::/48 22 5
   ```

### 交互式输入

如果您不提供命令行参数，程序将提示您输入主机名/IP/网段、端口和生成IP的数量。

## 输出文件

程序运行后，会在当前目录下生成一个名为 `rtts.csv` 的CSV文件，其中包含以下列：

- `ip`: 原始IP地址或主机名。
- `ip_with_brackets`: 格式化后的IP地址（IPv6地址会用方括号括起来）。
- `ip_port_with_brackets`: 格式化后的IP地址和端口（IPv6地址会用方括号括起来）。
- `延迟`: 连接延迟（毫秒）或错误信息。
