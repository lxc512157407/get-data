# 🌐 Pointend 威胁情报采集器 - 宝塔面板部署指南

## 📦 文件说明

| 文件 | 说明 | 用途 |
|------|------|------|
| `bt_panel_crawler.py` | 主爬虫脚本 | 核心采集逻辑 |
| `bt_crawler.sh` | Shell 启动脚本 | 宝塔计划任务调用 |
| `deploy.sh` | 一键部署脚本 | 快速部署到服务器 |

## 🚀 部署步骤

### 方法一：一键部署（推荐）

1. SSH 登录到你的服务器
2. 执行以下命令：

```bash
mkdir -p /www/server/pointend-data
cd /www/server/pointend-data

# 下载脚本（需要先上传文件）
# 或直接复制内容

# 创建数据库
python3 << 'PYEOF'
import sqlite3
db_path = "/www/server/pointend-data/attack_vectors.db"
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
print("✅ 数据库创建完成")
PYEOF

# 设置权限
chmod +x /www/server/pointend-data/bt_panel_crawler.py
chmod +x /www/server/pointend-data/bt_crawler.sh

# 测试运行
python3 /www/server/pointend-data/bt_panel_crawler.py
```

### 方法二：宝塔面板手动配置

1. **上传文件**
   - 将 `bt_panel_crawler.py` 上传到 `/www/server/pointend-data/`
   - 将 `bt_crawler.sh` 上传到 `/www/server/pointend-data/`

2. **创建数据库目录**
   ```bash
   mkdir -p /www/server/pointend-data
   mkdir -p /www/server/pointend-data/backup
   ```

3. **安装 Python 依赖**
   - 宝塔面板 -> 软件商店 -> Python项目管理器
   - 安装 Python 3.9+
   - 在终端执行：`pip3 install requests beautifulsoup4 feedparser`

4. **创建计划任务**
   - 宝塔面板 -> 计划任务
   - 添加 Shell 脚本任务
   - 任务名称：`Pointend 威胁情报采集`
   - 执行周期：`*/5 * * * *`（每5分钟）或 `*/10 * * * *`（每10分钟）
   - 脚本内容：
   ```bash
   cd /www/server/pointend-data
   python3 bt_panel_crawler.py >> crawler.log 2>&1
   ```

5. **保存并立即执行一次测试**

## 📊 数据源列表

### 🌍 国际数据源
- **NVD** - 美国国家漏洞数据库 (CVE)
- **OSV** - 开源漏洞数据库
- **GitHub Advisory** - GitHub 安全公告
- **Exploit-DB** - 漏洞利用代码库
- **MITRE ATT&CK** - 攻击战术技术库
- **CWE Top 25** - 最危险软件弱点列表
- **PortSwigger** - Web 安全研究
- **RSS 订阅** - 多个安全资讯源

### 🇨🇳 国内数据源
- **安全脉搏** - 安全资讯和文章

## 📁 目录结构

```
/www/server/pointend-data/
├── attack_vectors.db    # SQLite 数据库
├── bt_panel_crawler.py  # 主爬虫脚本
├── bt_crawler.sh        # Shell 启动脚本
├── crawler.log          # 运行日志
└── backup/              # 数据库备份目录
    └── attack_vectors_YYYYMMDD_HHMMSS.db
```

## 🔧 常见问题

### Q: 提示 "Python3 未找到"
**A:** 宝塔面板需要安装 Python 项目管理器，然后在软件商店安装 Python 3.9+

### Q: 依赖安装失败
**A:** 在宝塔终端执行：
```bash
pip3 install requests beautifulsoup4 feedparser -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: 数据库权限错误
**A:** 执行：
```bash
chown -R www:www /www/server/pointend-data
```

### Q: 中文乱码
**A:** 确保终端编码为 UTF-8：
```bash
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
```

## 📈 查看数据

```bash
# 查看数据总量
sqlite3 /www/server/pointend-data/attack_vectors.db "SELECT COUNT(*) FROM attack_vectors;"

# 按数据源统计
sqlite3 /www/server/pointend-data/attack_vectors.db "SELECT source, COUNT(*) FROM attack_vectors GROUP BY source ORDER BY COUNT(*) DESC;"

# 查看最新数据
sqlite3 /www/server/pointend-data/attack_vectors.db "SELECT title, source, collected_at FROM attack_vectors ORDER BY collected_at DESC LIMIT 10;"

# 查看运行日志
tail -50 /www/server/pointend-data/crawler.log
```

## 🔄 自动更新脚本

如果需要更新爬虫脚本，只需：
1. 下载最新的 `bt_panel_crawler.py`
2. 上传到服务器覆盖原文件
3. 重启计划任务或手动执行一次测试

---
最后更新：2026-05-07
版本：v2.1
