@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [了不起的TCP] 正在编译超小体积单文件 Windows 可执行程序...
go build -ldflags="-s -w" -o awesome_tcp.exe .
if errorlevel 1 (
    echo ❌ 编译失败，请确认本机已安装 Go 环境，可运行 go version 检查。
    pause
    exit /b 1
)
echo ✅ 编译成功！已生成单文件 awesome_tcp.exe，正在启动...
start "" "%~dp0awesome_tcp.exe"
