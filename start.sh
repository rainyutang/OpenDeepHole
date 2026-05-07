#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== OpenDeepHole 一键构建重启 ==="

# 1. 停止已有进程
echo "[1/4] 停止已有进程..."
pkill -f "uvicorn backend.main:app" 2>/dev/null && echo "  已停止 uvicorn" || echo "  uvicorn 未运行"
pkill -f "python.*mcp_server.server" 2>/dev/null && echo "  已停止 MCP Server" || echo "  MCP Server 未运行"
sleep 1

# 2. 构建前端
echo "[2/4] 构建前端..."
cd frontend
npm run build
cd "$SCRIPT_DIR"
echo "  前端构建完成"

# 3. 启动 MCP Server
echo "[3/4] 启动 MCP Server (port 8100)..."
python3 -m mcp_server.server &
MCP_PID=$!
sleep 2

# 4. 启动后端（前台运行，Ctrl+C 退出时清理 MCP 进程）
cleanup() {
    echo ""
    echo "正在停止服务..."
    kill $MCP_PID 2>/dev/null || true
    echo "已停止"
}
trap cleanup EXIT

echo "[4/4] 启动后端 (port 8000)..."
echo "=== 服务已启动，Ctrl+C 停止 ==="
uvicorn backend.main:app --host 0.0.0.0 --port 8000
