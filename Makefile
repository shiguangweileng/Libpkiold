CC = gcc
# OpenSSL安装路径，可根据不同环境修改
OPENSSL_DIR = /usr/local/openssl
CFLAGS = -I./include -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib64 -l:libcrypto.so.3 -lpthread
SRC_FILES = $(wildcard src/*.c)

WEB_CFLAGS = -I./include src/common.c src/imp_cert.c src/gm_crypto.c src/web_protocol.c

all: ca user test web

ca:
	@echo "正在编译CA服务器..."
	$(CC) server/ca-server/ca.c $(SRC_FILES) $(CFLAGS) -lmicrohttpd -o server/ca-server/ca
	@echo "CA服务器编译成功！"

user:
	@echo "正在编译User客户端..."
	$(CC) server/user-client/user.c $(SRC_FILES) $(CFLAGS) -lcurl -o server/user-client/user
	@echo "User客户端编译成功！"

test:
	@echo "正在编译func_test测试程序..."
	$(CC) server/user-client/func_test.c server/user-client/usercore.c $(SRC_FILES) $(CFLAGS) -lcurl -o server/user-client/func_test
	@echo "func_test测试程序编译成功！"

web: 
	@echo "正在编译CA Web程序..."
	$(CC) ca_web.c $(WEB_CFLAGS) -lmicrohttpd -ljson-c -lpthread -l:libcrypto.so.3 -o ca_web
	@echo "CA Web程序编译成功！"

clean:
	rm -f server/ca-server/ca
	rm -f server/user-client/user
	rm -f server/user-client/func_test
	rm -f ca_web
	@echo "清理完成！"

.PHONY: all ca user test web clean