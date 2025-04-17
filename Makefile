CC = gcc
# OpenSSL安装路径，可根据不同环境修改
OPENSSL_DIR = /usr/local/openssl
CFLAGS = -I./include -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib64 -l:libcrypto.so.3 -lpthread
SRC_FILES = $(wildcard src/*.c)

all: ca user

ca:
	@echo "正在编译CA服务器..."
	$(CC) server/ca-server/ca.c $(SRC_FILES) $(CFLAGS) -o server/ca-server/ca
	@echo "CA服务器编译成功！"

user:
	@echo "正在编译User客户端..."
	$(CC) server/user-client/user.c $(SRC_FILES) $(CFLAGS) -o server/user-client/user
	@echo "User客户端编译成功！"

web: mongoose
	@echo "正在编译Web监控程序..."
	$(CC) webmonitor/webmonitor.c webmonitor/mongoose.o -lpthread -o webmonitor/webmonitor
	@echo "Web监控程序编译成功！"

# 编译mongoose库(只在需要时编译)
mongoose:
	@if [ ! -f webmonitor/mongoose.o ]; then \
		echo "编译mongoose库..."; \
		$(CC) -Wall -c webmonitor/mongoose.c -o webmonitor/mongoose.o; \
	fi

clean:
	rm -f server/ca-server/ca
	rm -f server/user-client/user
	rm -f webmonitor/webmonitor
	@echo "清理完成！"

.PHONY: all ca user web mongoose clean 