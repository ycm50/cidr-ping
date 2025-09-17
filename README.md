# Telnet 延迟测试工具

这是一个用C语言编写的图形界面工具，用于测试到目标主机的TCP连接延迟（非TLS）。

## 编译

确保系统已安装GCC编译器和GTK+2.0开发库，然后运行：

```bash
make
```

如果编译时出现与GTK相关的错误，请确保已安装GTK+2.0开发库：

```bash
# Ubuntu/Debian:
sudo apt-get install libgtk2.0-dev

# CentOS/RHEL/Fedora:
sudo yum install gtk2-devel

# macOS (使用Homebrew):
brew install gtk+
```

## 使用方法

编译完成后，运行：

```bash
./telnet_delay_test
```

然后在图形界面中输入主机名和端口，点击"测试连接"按钮即可。

## 清理

要清理编译生成的文件，运行：

```bash
make clean
```