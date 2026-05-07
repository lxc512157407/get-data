#!/bin/bash
# ============================================
# 🌐 Pointend 威胁情报采集器 - 宝塔面板启动脚本
# ============================================
#
# 使用方法：
#   1. 将此脚本上传到服务器：/www/server/pointend-data/bt_crawler.sh
#   2. 宝塔面板 -> 计划任务 -> 添加 Shell 脚本
#   3. 脚本内容：bash /www/server/pointend-data/bt_crawler.sh
#   4. 执行周期：每 5-10 分钟
#
# 数据目录：/www/server/pointend-data/
# 日志文件：/www/server/pointend-data/crawler.log
# 数据库：  /www/server/pointend-data/attack_vectors.db
#
# ============================================

# 脚本目录
SCRIPT_DIR="/www/server/pointend-data"
CRAWLER_SCRIPT="$SCRIPT_DIR/bt_panel_crawler.py"
LOG_FILE="$SCRIPT_DIR/crawler.log"

# 创建目录
mkdir -p "$SCRIPT_DIR"

# 记录开始时间
echo "==========================================" >> "$LOG_FILE"
echo "🚀 采集任务开始: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
echo "==========================================" >> "$LOG_FILE"

# 检查 Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 未安装" >> "$LOG_FILE"
    echo "请在宝塔面板软件商店安装 Python3.9+"
    exit 1
fi

# 检查依赖
echo "📦 检查依赖..." >> "$LOG_FILE"
pip3 install requests beautifulsoup4 feedparser -q 2>/dev/null

# 执行爬虫
cd "$SCRIPT_DIR"
echo "🐍 开始执行爬虫..." >> "$LOG_FILE"
python3 "$CRAWLER_SCRIPT" >> "$LOG_FILE" 2>&1

# 记录结束时间
echo "✅ 采集任务完成: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# 显示最新日志
echo "=========================================="
echo "📊 最近采集日志："
tail -20 "$LOG_FILE"
echo "=========================================="
