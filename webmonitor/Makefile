CC = gcc
CFLAGS = -Wall -Wextra -I..
LDFLAGS = -lpthread

# mongoose源文件路径
MONGOOSE_SRC = mongoose.c

# 预编译的库文件
LIBS = mongoose.o

# 默认目标
all: webmonitor

# 编译mongoose库(只需要编译一次)
mongoose.o: $(MONGOOSE_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# 编译监控程序(使用预编译的mongoose.o)
webmonitor: webmonitor.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 运行监控程序
run: clean webmonitor
	./webmonitor

# 清理生成的文件(不删除mongoose.o)
clean:
	rm -f webmonitor webmonitor.o

.PHONY: all clean run
