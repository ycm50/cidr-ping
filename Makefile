# Makefile for telnet_delay_test

# Makefile for telnet_delay_test

# 编译器设置
ifeq ($(OS),Windows_NT)
    CC = gcc
    CFLAGS = -Wall -O2
    LIBS = -lws2_32
else
    # For POSIX systems (Linux, macOS, etc.)
    # If 'gcc' is not found, you might need to install it:
    # On Debian/Ubuntu: sudo apt-get install build-essential
    # On Fedora: sudo dnf groupinstall "Development Tools"
    CC = gcc
    CFLAGS = -Wall -O2
    LIBS =
endif

# 目录设置
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/buildfiles
BIN_DIR = $(BUILD_DIR)/bin

# 目标文件
TARGET_NAME = telnet_delay_test_general
SRC = $(TARGET_NAME).c

ifeq ($(OS),Windows_NT)
    TARGET = $(BIN_DIR)/$(TARGET_NAME).exe
else
    TARGET = $(BIN_DIR)/$(TARGET_NAME)
endif

OBJ = $(OBJ_DIR)/$(TARGET_NAME).o

# 创建必要的目录
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR))

# 默认目标
all: $(TARGET)

# 链接目标
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# 编译目标
$(OBJ_DIR)/$(TARGET_NAME).o: $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# 清理目标
clean:
	rm -f $(BIN_DIR)/$(TARGET_NAME) $(BIN_DIR)/$(TARGET_NAME).exe $(OBJ)
	rm -rf $(BUILD_DIR)

# 运行目标
run: $(TARGET)
	$(TARGET)

.PHONY: all clean run