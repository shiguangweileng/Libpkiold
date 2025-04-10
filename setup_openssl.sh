#!/bin/bash


# OpenSSL库路径
OPENSSL_LIB_PATH="/usr/local/openssl/lib"

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then 
    echo "请使用root权限运行此脚本"
    echo "使用方法: sudo ./setup_openssl.sh"
    exit 1
fi

# 检查OpenSSL库目录是否存在
if [ ! -d "$OPENSSL_LIB_PATH" ]; then
    echo "错误：OpenSSL库目录 $OPENSSL_LIB_PATH 不存在"
    exit 1
fi

# 检查/etc/ld.so.conf.d/目录是否存在
if [ ! -d "/etc/ld.so.conf.d" ]; then
    echo "错误：/etc/ld.so.conf.d/ 目录不存在"
    exit 1
fi

# 创建OpenSSL配置文件
echo "正在创建OpenSSL库配置文件..."
echo "$OPENSSL_LIB_PATH" > /etc/ld.so.conf.d/openssl.conf

# 更新动态链接库缓存
echo "正在更新动态链接库缓存..."
ldconfig

# 验证配置
echo "正在验证配置..."
if ldconfig -p | grep -q "$OPENSSL_LIB_PATH"; then
    echo "配置成功！OpenSSL库路径已添加到系统中"
    echo "您可以通过以下命令验证："
    echo "ldconfig -p | grep openssl"
else
    echo "警告：配置可能未生效，请检查系统日志"
fi 