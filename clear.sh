#!/bin/bash

# 获取脚本所在目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 设置ca-server目录和user-client目录
ca_server_dir="$SCRIPT_DIR/server/ca-server"
user_client_dir="$SCRIPT_DIR/server/user-client"

# 定义ca-server目录的白名单文件列表
ca_server_whitelist=("UserCerts" "UserData" "ca" "ca_priv.key" "ca_pub.key" "ca.c" "SerialNum.txt")

# 定义user-client目录的白名单文件列表
user_client_whitelist=("user" "user.c" "ca_pub.key" "auto_test.c" "ca.crt")

# 删除ca-server目录中不需要的文件
cd "$ca_server_dir" || { echo "无法进入目录 $ca_server_dir"; exit 1; }
for file in *; do
  if [[ ! " ${ca_server_whitelist[@]} " =~ " ${file} " ]]; then
    rm -f "$file"
    echo "已删除 $file"
  fi
done

# 清空UserCerts目录中的所有文件，但保留目录本身
if [ -d "$ca_server_dir/UserCerts" ]; then
  rm -f "$ca_server_dir/UserCerts"/*
  echo "UserCerts 目录中的文件已清空"
else
  echo "警告: UserCerts 目录不存在"
fi

# 清空目录中的所有文件，但保留目录本身
if [ -d "$ca_server_dir/UserData" ]; then
  rm -f "$ca_server_dir/UserData"/*
  echo "UserData 目录中的文件已清空"
else
  echo "警告: UserData 目录不存在"
fi

# 将SerialNum.txt内容置为1
if [ -f "$ca_server_dir/SerialNum.txt" ]; then
  echo "1" > "$ca_server_dir/SerialNum.txt"
else
  echo "警告: SerialNum.txt 文件不存在"
fi

# 删除user-client目录中不需要的文件
cd "$user_client_dir" || { echo "无法进入目录 $user_client_dir"; exit 1; }
for file in *; do
  if [[ ! " ${user_client_whitelist[@]} " =~ " ${file} " ]]; then
    rm -f "$file"
    echo "已删除 $file"
  fi
done

echo "清理完成！"