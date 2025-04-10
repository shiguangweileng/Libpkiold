#!/bin/bash

# 创建备份目录
BACKUP_DIR="./lib_backup"
mkdir -p "$BACKUP_DIR"

# 确保程序已编译
echo "首先编译所有程序..."
if [ -f "./build.sh" ]; then
    chmod +x ./build.sh
    ./build.sh
elif [ -f "./Makefile" ]; then
    make all
else
    echo "错误：未找到build.sh或Makefile"
    exit 1
fi

# 创建一个文件记录依赖信息
DEPS_FILE="$BACKUP_DIR/dependencies.txt"
echo "动态链接库依赖列表" > "$DEPS_FILE"
echo "生成时间: $(date)" >> "$DEPS_FILE"
echo "----------------------------------" >> "$DEPS_FILE"

# 分析ca程序的依赖
if [ -f "./server/ca-server/ca" ]; then
    echo -e "\n分析CA服务器依赖..."
    echo -e "\n== CA服务器依赖 ==" >> "$DEPS_FILE"
    ldd ./server/ca-server/ca >> "$DEPS_FILE"
    
    # 复制依赖库
    echo "备份CA服务器依赖库..."
    ldd ./server/ca-server/ca | grep "=> /" | awk '{print $3}' | while read -r lib; do
        if [ -f "$lib" ]; then
            cp "$lib" "$BACKUP_DIR/"
            echo "已复制: $lib"
        fi
    done
else
    echo "警告：CA服务器程序不存在，无法分析依赖"
fi

# 分析user程序的依赖
if [ -f "./server/user-client/user" ]; then
    echo -e "\n分析User客户端依赖..."
    echo -e "\n== User客户端依赖 ==" >> "$DEPS_FILE"
    ldd ./server/user-client/user >> "$DEPS_FILE"
    
    # 复制依赖库
    echo "备份User客户端依赖库..."
    ldd ./server/user-client/user | grep "=> /" | awk '{print $3}' | while read -r lib; do
        if [ -f "$lib" ]; then
            cp "$lib" "$BACKUP_DIR/"
            echo "已复制: $lib"
        fi
    done
else
    echo "警告：User客户端程序不存在，无法分析依赖"
fi

# 分析cost程序的依赖
if [ -f "./server/user-client/cost" ]; then
    echo -e "\n分析Cost程序依赖..."
    echo -e "\n== Cost程序依赖 ==" >> "$DEPS_FILE"
    ldd ./server/user-client/cost >> "$DEPS_FILE"
    
    # 复制依赖库
    echo "备份Cost程序依赖库..."
    ldd ./server/user-client/cost | grep "=> /" | awk '{print $3}' | while read -r lib; do
        if [ -f "$lib" ]; then
            cp "$lib" "$BACKUP_DIR/"
            echo "已复制: $lib"
        fi
    done
else
    echo "警告：Cost程序不存在，无法分析依赖"
fi

# 分析webmonitor程序的依赖
if [ -f "./webmonitor/webmonitor" ]; then
    echo -e "\n分析Web监控程序依赖..."
    echo -e "\n== Web监控程序依赖 ==" >> "$DEPS_FILE"
    ldd ./webmonitor/webmonitor >> "$DEPS_FILE"
    
    # 复制依赖库
    echo "备份Web监控程序依赖库..."
    ldd ./webmonitor/webmonitor | grep "=> /" | awk '{print $3}' | while read -r lib; do
        if [ -f "$lib" ]; then
            cp "$lib" "$BACKUP_DIR/"
            echo "已复制: $lib"
        fi
    done
else
    echo "警告：Web监控程序不存在，无法分析依赖"
fi

echo -e "\n所有依赖库已备份到 $BACKUP_DIR 目录"
echo "依赖信息已保存到 $DEPS_FILE"

# 创建README文件
cat > "$BACKUP_DIR/README.txt" << EOL
动态链接库备份目录
=================

此目录包含libpki项目所需的所有动态链接库文件。
在新系统上使用时，可以将这些库文件复制到系统库目录（如/usr/lib）或者使用LD_LIBRARY_PATH。

1.使用方法（临时）:
export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:完整路径/lib_backup

2.使用方法（永久）:
将所有.so文件复制到系统的库目录，如：
sudo cp *.so /usr/lib/
或者：
添加动态链接库路径：
把动态链接库所在的路径添加到/etc/ld.so.conf中
include /etc/ld.so.conf.d/*.conf
或者是/usr/local/lib64

然后运行:
sudo ldconfig

详细的依赖信息可以在dependencies.txt文件中查看。
EOL

echo "创建了使用说明文件 $BACKUP_DIR/README.txt"
echo "备份完成！" 