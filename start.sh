#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== DeepHole 2.0 一键构建重启 ==="

# 1. 停止已有进程
echo "[1/3] 停止已有进程..."
pkill -f "uvicorn backend.main:app" 2>/dev/null && echo "  已停止 uvicorn" || echo "  uvicorn 未运行"
sleep 1

# 2. 构建前端
echo "[2/3] 构建前端..."
if [ -d frontend ]; then
  cd frontend
  npm run build
  cd "$SCRIPT_DIR"
  echo "  前端构建完成"
else
  echo "  使用镜像内预构建的前端静态文件"
fi

# 3. 启动后端（前台运行）
echo "[3/3] 启动后端 (port 8000)..."
echo "=== 服务已启动，Ctrl+C 停止 ==="
WS_PING_INTERVAL="${OPENDEEPHOLE_SERVER_WS_PING_INTERVAL:-30}"
WS_PING_TIMEOUT="${OPENDEEPHOLE_SERVER_WS_PING_TIMEOUT:-120}"
DATABASE_URL="${OPENDEEPHOLE_DATABASE_URL:-}"
if [ -n "${OPENDEEPHOLE_SERVER_WORKERS:-}" ]; then
  SERVER_WORKERS="$OPENDEEPHOLE_SERVER_WORKERS"
elif [[ "$DATABASE_URL" == postgres://* || "$DATABASE_URL" == postgresql://* ]]; then
  SERVER_WORKERS=4
else
  SERVER_WORKERS=1
fi
if ! [[ "$SERVER_WORKERS" =~ ^[1-9][0-9]*$ ]]; then
  echo "错误：OPENDEEPHOLE_SERVER_WORKERS 必须是正整数" >&2
  exit 2
fi
if [ "$SERVER_WORKERS" -gt 1 ] && ! [[ "$DATABASE_URL" == postgres://* || "$DATABASE_URL" == postgresql://* ]]; then
  echo "错误：多 Worker 模式必须设置 OPENDEEPHOLE_DATABASE_URL=postgresql://..." >&2
  exit 2
fi
if [[ "$DATABASE_URL" == postgres://* || "$DATABASE_URL" == postgresql://* ]]; then
  STORAGE_MODE="PostgreSQL"
else
  STORAGE_MODE="SQLite/单 Worker"
fi
echo "  存储模式: $STORAGE_MODE"
echo "  后端 Worker: $SERVER_WORKERS"
python3 -m uvicorn backend.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers "$SERVER_WORKERS" \
  --ws-ping-interval "$WS_PING_INTERVAL" \
  --ws-ping-timeout "$WS_PING_TIMEOUT"
