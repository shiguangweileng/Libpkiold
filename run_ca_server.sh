#!/bin/bash

echo "===== 启动 PKI 系统 ====="
echo "- 前端：http://localhost:5173"
echo "- CA Web API：http://localhost:8888"
echo "- CA 服务：运行在后台"
echo "============================="

# 进入前端目录并启动所有服务
cd webui && npm run start-all 