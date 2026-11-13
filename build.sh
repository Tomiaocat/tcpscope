#!/usr/bin/env bash
set -e
echo "[了不起的TCP] 正在编译超小体积单文件可执行程序..."
go build -ldflags="-s -w" -o awesome_tcp .
echo "✅ 编译成功！生成单文件: ./awesome_tcp"
./awesome_tcp
