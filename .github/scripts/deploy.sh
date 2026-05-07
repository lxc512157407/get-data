#!/bin/bash
# ============================================
# 🌐 Pointend 威胁情报采集器 - 一键部署脚本
# ============================================
#
# 在服务器上以 root 权限执行：
#   wget https://raw.githubusercontent.com/你的用户名/get-data/main/.github/scripts/deploy.sh
#   bash deploy.sh
#
# 或直接复制以下内容到宝塔终端执行：
#   mkdir -p /www/server/pointend-data
#   cd /www/server/pointend-data
#   # 然后上传 bt_panel_crawler.py 和 bt_crawler.sh
#
# ============================================

set -e

echo "=========================================="
echo "🌐 Pointend 威胁情报采集器 - 部署脚本"
echo "=========================================="

# 创建数据目录
DATA_DIR="/www/server/pointend-data"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/backup"
mkdir -p "$DATA_DIR/logs"

echo "✅ 数据目录创建完成: $DATA_DIR"

# 安装依赖
echo "📦 安装 Python 依赖..."
pip3 install requests beautifulsoup4 feedparser -q

echo "✅ 依赖安装完成"

# 设置权限
chmod +x "$DATA_DIR/bt_panel_crawler.py"
chmod +x "$DATA_DIR/bt_crawler.sh"

echo "✅ 权限设置完成"

# 创建测试数据库
if [ ! -f "$DATA_DIR/attack_vectors.db" ]; then
    python3 << EOF
import sqlite3
import os
db_path = "$DATA_DIR/attack_vectors.db"
conn = sqlite3.connect(db_path)
conn.execute("""
CREATE TABLE IF NOT EXISTS attack_vectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT UNIQUE,
    source TEXT,
    category TEXT DEFAULT 'intelligence',
    created_at TEXT,
    collected_at TEXT
)
""")
conn.commit()
conn.close()
print("✅ 数据库初始化完成")
EOF
fi

echo ""
echo "=========================================="
echo "🎉 部署完成！"
echo "=========================================="
echo ""
echo "📁 数据目录: $DATA_DIR"
echo "📄 主脚本:   $DATA_DIR/bt_panel_crawler.py"
echo "🔧 启动脚本: $DATA_DIR/bt_crawler.sh"
echo "📊 数据库:   $DATA_DIR/attack_vectors.db"
echo "📝 日志:     $DATA_DIR/crawler.log"
echo ""
echo "下一步："
echo "1. 宝塔面板 -> 计划任务 -> 添加 Shell 脚本"
echo "2. 脚本内容: bash $DATA_DIR/bt_crawler.sh"
echo "3. 执行周期: 每 5-10 分钟"
echo "4. 保存即可"
echo ""
echo "手动测试："
echo "  python3 $DATA_DIR/bt_panel_crawler.py"
echo ""
echo "=========================================="
