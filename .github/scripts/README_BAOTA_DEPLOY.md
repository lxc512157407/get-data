# 🌐 Pointend 威胁情报采集器 - 宝塔面板部署指南

## 📋 概述

本文档说明如何将 Pointend 威胁情报采集器部署到宝塔面板，实现自动化定时采集威胁情报数据。

---

## 📁 文件清单

| 文件 | 用途 |
|------|------|
| `bt_panel_crawler.py` | 宝塔版主爬虫脚本（核心采集逻辑） |
| `bt_crawler.sh` | Shell 启动脚本（宝塔计划任务调用） |
| `deploy.sh` | 一键部署脚本（快速部署到服务器） |

---

## 🚀 快速部署

### 方法一：一键部署（推荐）

SSH 登录服务器，执行以下命令：

```bash
mkdir -p /www/server/pointend-data
cd /www/server/pointend-data

# 下载主脚本
cat > bt_panel_crawler.py << 'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import random
import sqlite3
import re
from datetime import datetime
from typing import List, Optional

try:
    import requests
except ImportError:
    os.system("pip install requests -q")
    import requests

try:
    import feedparser
except ImportError:
    os.system("pip install feedparser -q")
    import feedparser

try:
    from bs4 import BeautifulSoup
except ImportError:
    os.system("pip install beautifulsoup4 -q")
    from bs4 import BeautifulSoup


DB_PATH = "/www/server/pointend-data/attack_vectors.db"
LOG_PATH = "/www/server/pointend-data/crawler.log"
BACKUP_DIR = "/www/server/pointend-data/backup"


def log(msg: str):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {msg}"
    print(log_line)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(log_line + '\n')
    except:
        pass


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    init_db()
    return conn


def insert_vector(conn, title: str, source: str, category: str = "intelligence") -> bool:
    cursor = conn.execute("""
    INSERT OR IGNORE INTO attack_vectors (title, source, category, created_at, collected_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        title,
        source,
        category,
        datetime.now().isoformat(),
        datetime.now().isoformat()
    ))
    conn.commit()
    return cursor.rowcount > 0


class ThreatCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        self.timeout = 30
        self.retry_delay = 5

    def _request_with_retry(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        for attempt in range(3):
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                response.raise_for_status()
                if response.encoding is None or response.encoding == 'ISO-8859-1':
                    if any(domain in url.lower() for domain in ['freebuf', 'secrss', '51testing', 'nosec', 'wooyun', 'vulhub']):
                        response.encoding = 'GBK'
                    else:
                        response.encoding = response.apparent_encoding
                return response
            except Exception:
                if attempt < 2:
                    time.sleep(self.retry_delay * (attempt + 1) + random.uniform(0, 2))
                    continue
                return None

    def _clean_text(self, text: str, max_len: int = 100) -> str:
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        if len(text) > max_len:
            text = text[:max_len] + "..."
        return text

    def crawl_nvd_cves(self, limit: int = 30) -> List[str]:
        results = []
        log("  🕵️ [NVD] 爬取国家漏洞数据库...")
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'resultsPerPage': limit, 'startIndex': 0}
            response = self._request_with_retry(url, params=params)
            if response:
                data = response.json()
                for cve in data.get('vulnerabilities', []):
                    cve_id = cve.get('cve', {}).get('id', '')
                    desc = cve.get('cve', {}).get('descriptions', [{}])[0].get('value', '')
                    if cve_id and desc:
                        title = f"NVD-{cve_id}: {self._clean_text(desc, 80)}"
                        results.append(title)
                log(f"  ✅ [NVD] 获取 {len(results)} 条 CVE 漏洞")
        except Exception as e:
            log(f"  ⚠️ [NVD] 解析失败: {e}")
        return results

    def crawl_osv(self, limit: int = 15) -> List[str]:
        results = []
        log("  🕵️ [OSV] 爬取开源漏洞库...")
        try:
            url = "https://osv.dev/list"
            response = self._request_with_retry(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)[:limit]
                for link in links:
                    text = link.text.strip()
                    if text and len(text) > 5:
                        results.append(f"OSV: {self._clean_text(text, 80)}")
                log(f"  ✅ [OSV] 获取 {len(results)} 条开源漏洞")
        except Exception as e:
            log(f"  ⚠️ [OSV] 解析失败: {e}")
        return results

    def crawl_github_advisories(self, limit: int = 15) -> List[str]:
        results = []
        log("  🕵️ [GHSA] 爬取 GitHub 安全公告...")
        try:
            url = "https://api.github.com/advisories"
            params = {'per_page': limit, 'direction': 'desc'}
            response = self._request_with_retry(url, params=params)
            if response:
                data = response.json()
                for advisory in data:
                    ghsa_id = advisory.get('ghsa_id', '')
                    summary = advisory.get('summary', '')
                    severity = advisory.get('severity', 'unknown')
                    if ghsa_id and summary:
                        title = f"GHSA-{ghsa_id}: {self._clean_text(summary, 70)} [{severity}]"
                        results.append(title)
                log(f"  ✅ [GHSA] 获取 {len(results)} 条安全公告")
        except Exception as e:
            log(f"  ⚠️ [GHSA] 解析失败: {e}")
        return results

    def crawl_exploit_db(self, limit: int = 10) -> List[str]:
        results = []
        log("  🕵️ [Exploit-DB] 爬取漏洞利用库...")
        try:
            url = "https://www.exploit-db.com/rss.xml"
            response = self._request_with_retry(url)
            if response:
                import warnings
                from bs4 import XMLParsedAsHTMLWarning
                warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
                soup = BeautifulSoup(response.text, 'html.parser')
                items = soup.find_all('item')[:limit]
                for item in items:
                    title = item.find('title')
                    if title and title.text.strip():
                        results.append(f"Exploit-DB: {self._clean_text(title.text, 80)}")
                log(f"  ✅ [Exploit-DB] 获取 {len(results)} 条利用代码")
        except Exception as e:
            log(f"  ⚠️ [Exploit-DB] 解析失败: {e}")
        return results

    def crawl_mitre_attack(self) -> List[str]:
        results = []
        log("  🕵️ [MITRE] 爬取 ATT&CK 战术技术...")
        try:
            url = "https://attack.mitre.org/"
            response = self._request_with_retry(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.select('.technique-link, a[href*="techniques"]')[:20]
                for elem in elements:
                    text = elem.text.strip()
                    if text and len(text) > 5:
                        results.append(f"MITRE-ATTACK: {self._clean_text(text, 60)}")
                log(f"  ✅ [MITRE] 获取 {len(results)} 条战术技术")
        except Exception:
            pass
        if not results:
            log("  ⚠️ [MITRE] 使用备用数据...")
            backup_data = [
                "MITRE-ATTACK: T1190 - Exploit Public-Facing Application",
                "MITRE-ATTACK: T1133 - External Remote Services",
                "MITRE-ATTACK: T1078 - Valid Accounts",
                "MITRE-ATTACK: T1050 - New Service",
                "MITRE-ATTACK: T1053 - Scheduled Task/Job",
            ]
            results = backup_data
            log(f"  ✅ [MITRE] 备用数据 {len(results)} 条")
        return results[:20]

    def crawl_cwe_top25(self) -> List[str]:
        results = []
        log("  🕵️ [CWE] 爬取 Top 25 最危险弱点...")
        try:
            url = "https://cwe.mitre.org/top25/"
            response = self._request_with_retry(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()
                cwe_matches = re.findall(r'CWE-\d+[^\s,]*', text)[:25]
                seen = set()
                for match in cwe_matches:
                    match = match.strip()
                    if match not in seen and len(match) < 30:
                        seen.add(match)
                        results.append(f"CWE-Top25: {match}")
                log(f"  ✅ [CWE] 获取 {len(results)} 条最危险弱点")
        except Exception:
            pass
        if not results:
            log("  ⚠️ [CWE] 使用备用数据...")
            backup_data = [
                "CWE-Top25: CWE-787 - Out-of-bounds Write",
                "CWE-Top25: CWE-79 - Improper Neutralization of Input During Web Page Generation",
                "CWE-Top25: CWE-89 - SQL Injection",
                "CWE-Top25: CWE-416 - Use After Free",
                "CWE-Top25: CWE-78 - OS Command Injection",
            ]
            results = backup_data
            log(f"  ✅ [CWE] 备用数据 {len(results)} 条")
        return results[:25]

    def crawl_portswigger(self, limit: int = 8) -> List[str]:
        results = []
        log("  🕵️ [PortSwigger] 爬取 Web 安全研究...")
        try:
            url = "https://portswigger.net/research"
            response = self._request_with_retry(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['h2', 'h3'])[:limit]
                for elem in elements:
                    text = elem.text.strip()
                    if text and len(text) > 15:
                        results.append(f"PortSwigger: {self._clean_text(text, 80)}")
                log(f"  ✅ [PortSwigger] 获取 {len(results)} 条安全研究")
        except Exception as e:
            log(f"  ⚠️ [PortSwigger] 解析失败: {e}")
        return results

    def crawl_security_rss(self) -> List[str]:
        results = []
        rss_feeds = [
            ("https://feeds.feedburner.com/TheHackersNews", "THN"),
            ("https://security.googleblog.com/feeds/posts/default", "GoogleSec"),
            ("https://www.schneier.com/feed/atom/", "Schneier"),
            ("https://krebsonsecurity.com/feed/", "KrebsOnSecurity"),
            ("https://threatpost.com/feed/", "ThreatPost"),
        ]
        log("  🕵️ [RSS] 爬取安全资讯订阅...")
        for feed_url, source in rss_feeds:
            try:
                feed = feedparser.parse(feed_url)
                count = 0
                for entry in feed.entries[:5]:
                    title = self._clean_text(entry.title)
                    if title:
                        results.append(f"RSS-{source}: {title}")
                        count += 1
                if count > 0:
                    log(f"    ✅ {source}: +{count} 条")
            except Exception:
                log(f"    ⚠️ {source} 解析失败")
        log(f"  ✅ [RSS] 共获取 {len(results)} 条资讯")
        return results

    def crawl_chinese_sources(self) -> List[str]:
        results = []
        log("  🕵️ [安全脉搏] 爬取安全文章...")
        try:
            url = "https://www.secrss.com"
            response = self._request_with_retry(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['h2', 'h3'])[:5]
                for elem in elements:
                    text = elem.text.strip()
                    if text and len(text) > 10:
                        results.append(f"安全脉搏: {self._clean_text(text, 80)}")
                log(f"  ✅ [安全脉搏] 获取 {len(results)} 篇文章")
        except Exception:
            log(f"  ⚠️ [安全脉搏] 解析失败")
        return results


def backup_db():
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(BACKUP_DIR, f"attack_vectors_{timestamp}.db")
        with open(DB_PATH, 'rb') as src:
            with open(backup_path, 'wb') as dst:
                dst.write(src.read())
        import glob
        backups = sorted(glob.glob(os.path.join(BACKUP_DIR, "attack_vectors_*.db")))
        if len(backups) > 10:
            for old_backup in backups[:-10]:
                os.remove(old_backup)
        log(f"📦 数据库已备份: {backup_path}")
    except Exception as e:
        log(f"⚠️ 备份失败: {e}")


def main():
    print("=" * 60)
    print("🌐 Pointend 威胁情报采集器 v2.1 (宝塔版)")
    print("=" * 60)
    log("=" * 60)
    log("🌐 Pointend 威胁情报采集器启动...")
    crawler = ThreatCrawler()
    all_vectors = []
    log("🌍 国际数据源爬取中...")
    all_vectors.extend(crawler.crawl_nvd_cves())
    all_vectors.extend(crawler.crawl_osv())
    all_vectors.extend(crawler.crawl_github_advisories())
    all_vectors.extend(crawler.crawl_exploit_db())
    all_vectors.extend(crawler.crawl_mitre_attack())
    all_vectors.extend(crawler.crawl_cwe_top25())
    all_vectors.extend(crawler.crawl_portswigger())
    all_vectors.extend(crawler.crawl_security_rss())
    log("🇨🇳 国内数据源爬取中...")
    all_vectors.extend(crawler.crawl_chinese_sources())
    log("📦 开始入库...")
    with get_db() as db:
        added = 0
        for vector in all_vectors:
            if insert_vector(db, vector, "bt-crawler-v2"):
                added += 1
        cursor = db.execute("SELECT COUNT(*) FROM attack_vectors")
        total = cursor.fetchone()[0]
        log(f"✅ 新增 {added} 条")
        log(f"📊 总计 {total} 条")
    backup_db()
    print(f"✅ 采集完成！新增 {added} 条威胁情报")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF

# 下载启动脚本
cat > bt_crawler.sh << 'SHEOF'
#!/bin/bash
SCRIPT_DIR="/www/server/pointend-data"
CRAWLER_SCRIPT="$SCRIPT_DIR/bt_panel_crawler.py"
LOG_FILE="$SCRIPT_DIR/crawler.log"
mkdir -p "$SCRIPT_DIR"
echo "==========================================" >> "$LOG_FILE"
echo "🚀 采集任务开始: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
echo "==========================================" >> "$LOG_FILE"
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 未安装" >> "$LOG_FILE"
    exit 1
fi
echo "📦 检查依赖..." >> "$LOG_FILE"
pip3 install requests beautifulsoup4 feedparser -q 2>/dev/null
cd "$SCRIPT_DIR"
echo "🐍 开始执行爬虫..." >> "$LOG_FILE"
python3 "$CRAWLER_SCRIPT" >> "$LOG_FILE" 2>&1
echo "✅ 采集任务完成: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"
tail -20 "$LOG_FILE"
SHEOF

# 设置权限
chmod +x bt_panel_crawler.py
chmod +x bt_crawler.sh

# 创建数据库
python3 << 'DBEOF'
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
DBEOF

echo ""
echo "🎉 部署完成！"
echo "下一步：宝塔面板 -> 计划任务 -> 添加 Shell 脚本"
echo "脚本内容：bash /www/server/pointend-data/bt_crawler.sh"
```

### 方法二：宝塔面板手动配置

1. **上传文件**
   - 将 `bt_panel_crawler.py` 上传到 `/www/server/pointend-data/`
   - 将 `bt_crawler.sh` 上传到 `/www/server/pointend-data/`

2. **安装依赖**
   宝塔终端执行：
   ```bash
   pip3 install requests beautifulsoup4 feedparser
   ```

3. **创建数据库**
   ```bash
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
   ```

4. **添加计划任务**
   - 宝塔面板 → 计划任务 → 添加 Shell 脚本任务
   - 任务名称：`Pointend 威胁情报采集`
   - 执行周期：`*/5 * * * *`（每5分钟）
   - 脚本内容：
   ```bash
   cd /www/server/pointend-data
   python3 bt_panel_crawler.py >> crawler.log 2>&1
   ```

---

## 📊 数据源

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

---

## 📁 目录结构

```
/www/server/pointend-data/
├── attack_vectors.db     # SQLite 数据库
├── bt_panel_crawler.py  # 主爬虫脚本
├── bt_crawler.sh        # Shell 启动脚本
├── crawler.log           # 运行日志
└── backup/              # 数据库备份目录
    └── attack_vectors_YYYYMMDD_HHMMSS.db
```

---

## 🔧 常用命令

```bash
# 查看数据总量
sqlite3 /www/server/pointend-data/attack_vectors.db "SELECT COUNT(*) FROM attack_vectors;"

# 按数据源统计
sqlite3 /www/server/pointend-data/attack_vectors.db "SELECT source, COUNT(*) FROM attack_vectors GROUP BY source ORDER BY COUNT(*) DESC;"

# 查看最新数据
sqlite3 /www/server/pointend-data/attack_vectors.db "SELECT title, source, collected_at FROM attack_vectors ORDER BY collected_at DESC LIMIT 10;"

# 查看运行日志
tail -50 /www/server/pointend-data/crawler.log

# 手动执行采集
python3 /www/server/pointend-data/bt_panel_crawler.py
```

---

## ❓ 常见问题

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

---

## 📝 更新日志

- **v2.1 (2026-05-07)**
  - 修复中文编码问题
  - 添加数据库自动备份
  - 优化重试机制
  - 增加更多 RSS 数据源

- **v2.0 (2026-05-06)**
  - 重构代码结构
  - 增加国际数据源
  - 支持宝塔面板部署

---

最后更新：2026-05-07
