#!/bin/bash
# ===========================================
# Pointend 威胁情报采集器 - 宝塔面板计划任务脚本
# ===========================================
# 安装路径
CRAWLER_DIR="/www/server/pointend-data"
LOG_FILE="${CRAWLER_DIR}/crawler.log"

# 创建目录
mkdir -p ${CRAWLER_DIR}

# 记录开始时间
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🚀 开始采集威胁情报..." >> ${LOG_FILE}

# 执行采集脚本
cd ${CRAWLER_DIR}
python3 ${CRAWLER_DIR}/bt_panel_crawler.py >> ${LOG_FILE} 2>&1

# 记录结束时间
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 采集任务完成" >> ${LOG_FILE}
echo "----------------------------------------" >> ${LOG_FILE}

# 输出完成信息
echo "✅ 采集任务完成，详见 ${LOG_FILE}"
