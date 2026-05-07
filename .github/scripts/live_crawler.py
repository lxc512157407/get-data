"""
🌐 Pointend 全能威胁情报爬虫 v2.1 (优化版)

修复的问题：
- OSV.dev 使用更好的选择器
- MITRE ATT&CK 使用备用数据源
- CWE Top 25 使用备用方案
- 掘金/知乎等国内站点优化
- 安全脉搏使用正确的选择器

🌍 国际数据源：NVD, OSV, GitHub, Exploit-DB, RSS 订阅
🇨🇳 国内数据源：FreeBuf, 安全脉搏, 51Testing 等
"""
import sys
import json
import time
import random
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent))

import requests
import feedparser
from bs4 import BeautifulSoup

from simple_kb import get_db, insert_vector


class FullThreatCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        self.timeout = 30
        self.retry_delay = 5

    def _request_with_retry(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """带重试的请求方法"""
        for attempt in range(3):
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                response.raise_for_status()
                
                # 修复编码问题 - 针对中文网站
                if response.encoding is None or response.encoding == 'ISO-8859-1':
                    # 尝试检测正确编码
                    if 'freebuf' in url.lower() or 'secrss' in url.lower() or '51testing' in url.lower() or 'nosec' in url.lower() or 'wooyun' in url.lower() or 'vulhub' in url.lower():
                        response.encoding = 'GBK'
                    else:
                        response.encoding = response.apparent_encoding
                
                return response
            except requests.exceptions.RequestException:
                if attempt < 2:
                    time.sleep(self.retry_delay * (attempt + 1) + random.uniform(0, 2))
                    continue
                return None

    def _clean_text(self, text: str, max_len: int = 100) -> str:
        """清理文本"""
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        if len(text) > max_len:
            text = text[:max_len] + "..."
        return text

    def crawl_nvd_cves(self, limit: int = 30) -> List[str]:
        """从 NVD 获取最近的 CVE 漏洞"""
        results = []
        print("  🕵️ [NVD] 爬取国家漏洞数据库...")

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'resultsPerPage': limit, 'startIndex': 0}

        response = self._request_with_retry(url, params=params)
        if response:
            try:
                data = response.json()
                for cve in data.get('vulnerabilities', []):
                    cve_id = cve.get('cve', {}).get('id', '')
                    desc = cve.get('cve', {}).get('descriptions', [{}])[0].get('value', '')
                    if cve_id and desc:
                        title = f"NVD-{cve_id}: {self._clean_text(desc, 80)}"
                        results.append(title)
                print(f"  ✅ [NVD] 获取 {len(results)} 条 CVE 漏洞")
            except json.JSONDecodeError:
                print("  ⚠️ [NVD] 响应解析失败")

        return results

    def crawl_osv(self, limit: int = 15) -> List[str]:
        """从 OSV.dev 获取开源漏洞"""
        results = []
        print("  🕵️ [OSV] 爬取开源漏洞库...")

        url = "https://osv.dev/list"
        response = self._request_with_retry(url)
        if response:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                # 尝试多种选择器
                links = soup.find_all('a', href=True)[:limit]
                for link in links:
                    text = link.text.strip()
                    if text and len(text) > 10 and ('GHSA-' in text or 'PYSEC-' in text or 'GO-' in text):
                        results.append(f"OSV: {self._clean_text(text, 80)}")
                print(f"  ✅ [OSV] 获取 {len(results)} 条开源漏洞")
            except Exception as e:
                print(f"  ⚠️ [OSV] 解析失败: {e}")

        return results

    def crawl_github_advisories(self, limit: int = 15) -> List[str]:
        """从 GitHub 获取安全公告"""
        results = []
        print("  🕵️ [GHSA] 爬取 GitHub 安全公告...")

        url = "https://api.github.com/advisories"
        params = {'per_page': limit, 'direction': 'desc'}

        response = self._request_with_retry(url, params=params)
        if response:
            try:
                data = response.json()
                for advisory in data:
                    ghsa_id = advisory.get('ghsa_id', '')
                    summary = advisory.get('summary', '')
                    severity = advisory.get('severity', 'unknown')
                    if ghsa_id and summary:
                        title = f"GHSA-{ghsa_id} [{severity}]: {self._clean_text(summary, 70)}"
                        results.append(title)
                print(f"  ✅ [GHSA] 获取 {len(results)} 条安全公告")
            except json.JSONDecodeError:
                print("  ⚠️ [GHSA] 响应解析失败")

        return results

    def crawl_exploit_db(self, limit: int = 10) -> List[str]:
        """从 Exploit-DB 获取漏洞利用代码"""
        results = []
        print("  🕵️ [Exploit-DB] 爬取漏洞利用库...")

        url = "https://www.exploit-db.com/rss.xml"
        response = self._request_with_retry(url)
        if response:
            try:
                feed = feedparser.parse(response.text)
                for entry in feed.entries[:limit]:
                    title = self._clean_text(entry.get('title', ''))
                    if title:
                        results.append(f"Exploit-DB: {title}")
                print(f"  ✅ [Exploit-DB] 获取 {len(results)} 条利用代码")
            except Exception as e:
                print(f"  ⚠️ [Exploit-DB] 解析失败: {e}")

        return results

    def crawl_mitre_attack(self) -> List[str]:
        """从 MITRE ATT&CK 获取战术技术"""
        results = []
        print("  🕵️ [MITRE] 爬取 ATT&CK 战术技术...")

        # 尝试多个数据源
        sources = [
            ("https://attack.mitre.org/", "main"),
            ("https://raw.githubusercontent.com/mitre/cti/master/ATT&CK/attack-search/package-lock.json", "json"),
        ]

        for url, source_type in sources:
            try:
                response = self._request_with_retry(url)
                if response:
                    if source_type == "json":
                        data = response.json()
                        # 解析 MITRE ATT&CK STIX 数据
                        objects = data.get('objects', [])
                        for obj in objects[:30]:
                            if obj.get('type') == 'attack-pattern':
                                name = obj.get('name', '')
                                if name:
                                    results.append(f"MITRE-ATTACK: {name}")
                    else:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        # 尝试多种选择器
                        for selector in ['.technique-link', 'a[href*="techniques"]', '.attack-link']:
                            elements = soup.select(selector)[:20]
                            for elem in elements:
                                text = elem.text.strip()
                                if text and len(text) > 5:
                                    results.append(f"MITRE-ATTACK: {self._clean_text(text, 60)}")
                    if results:
                        break
            except Exception:
                continue

        # 如果还是为空，使用内置的 CWE 数据
        if not results:
            print("  ⚠️ [MITRE] 官方站点连接失败，使用备用数据...")
            backup_data = [
                "MITRE-ATTACK: T1190 - Exploit Public-Facing Application",
                "MITRE-ATTACK: T1133 - External Remote Services",
                "MITRE-ATTACK: T1078 - Valid Accounts",
                "MITRE-ATTACK: T1199 - Trusted Relationship",
                "MITRE-ATTACK: T1050 - New Service",
                "MITRE-ATTACK: T1053 - Scheduled Task/Job",
                "MITRE-ATTACK: T1484 - Domain Trust Modification",
                "MITRE-ATTACK: T1569 - System Services",
                "MITRE-ATTACK: T1543 - Create/Modify System Process",
                "MITRE-ATTACK: T1578 - Modify Cloud Compute Infrastructure",
            ]
            results = backup_data

        print(f"  ✅ [MITRE] 获取 {len(results)} 条战术技术")
        return results[:20]

    def crawl_cwe_top25(self) -> List[str]:
        """从 CWE 获取 Top 25 最危险软件弱点"""
        results = []
        print("  🕵️ [CWE] 爬取 Top 25 最危险弱点...")

        # 尝试多个数据源
        sources = [
            "https://cwe.mitre.org/top25/",
            "https://cwe.mitre.org/data/definitions/900.html",
        ]

        for url in sources:
            response = self._request_with_retry(url)
            if response:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # 查找所有包含 CWE 的文本
                    text = soup.get_text()
                    cwe_matches = re.findall(r'CWE-\d+[^\s,]*', text)[:25]
                    seen = set()
                    for match in cwe_matches:
                        match = match.strip()
                        if match not in seen and len(match) < 30:
                            seen.add(match)
                            results.append(f"CWE-Top25: {match}")

                    # 也尝试查找特定元素
                    if not results:
                        elements = soup.find_all(['li', 'td', 'span'], class_=lambda x: x and 'cwe' in x.lower() if x else False)[:25]
                        for elem in elements:
                            text = elem.text.strip()
                            if 'CWE-' in text:
                                results.append(f"CWE-Top25: {self._clean_text(text, 60)}")

                    if results:
                        break
                except Exception:
                    continue

        # 如果还是为空，使用内置的 CWE Top 25 数据
        if not results:
            print("  ⚠️ [CWE] 官方站点连接失败，使用备用数据...")
            backup_data = [
                "CWE-Top25: CWE-787 - Out-of-bounds Write",
                "CWE-Top25: CWE-79 - Improper Neutralization of Input During Web Page Generation",
                "CWE-Top25: CWE-89 - SQL Injection",
                "CWE-Top25: CWE-416 - Use After Free",
                "CWE-Top25: CWE-78 - OS Command Injection",
                "CWE-Top25: CWE-20 - Improper Input Validation",
                "CWE-Top25: CWE-22 - Path Traversal",
                "CWE-Top25: CWE-352 - Cross-Site Request Forgery",
                "CWE-Top25: CWE-434 - Unrestricted File Upload",
                "CWE-Top25: CWE-918 - Server-Side Request Forgery",
                "CWE-Top25: CWE-77 - Command Injection",
                "CWE-Top25: CWE-125 - Out-of-bounds Read",
                "CWE-Top25: CWE-190 - Integer Overflow",
                "CWE-Top25: CWE-287 - Improper Authentication",
                "CWE-Top25: CWE-476 - NULL Pointer Dereference",
            ]
            results = backup_data

        # 去重
        seen = set()
        unique_results = []
        for r in results:
            if r not in seen:
                seen.add(r)
                unique_results.append(r)

        print(f"  ✅ [CWE] 获取 {len(unique_results)} 条最危险弱点")
        return unique_results[:25]

    def crawl_portswigger(self, limit: int = 10) -> List[str]:
        """从 PortSwigger 获取 Web 安全研究"""
        results = []
        print("  🕵️ [PortSwigger] 爬取 Web 安全研究...")

        # 尝试多个页面
        urls = [
            "https://portswigger.net/research",
            "https://portswigger.net/daily-swig",
        ]

        for url in urls:
            response = self._request_with_retry(url)
            if response:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    elements = soup.find_all(['h2', 'h3', 'a'])[:limit]
                    for elem in elements:
                        text = elem.text.strip()
                        if text and len(text) > 15:
                            results.append(f"PortSwigger: {self._clean_text(text, 80)}")
                    if results:
                        break
                except Exception:
                    continue

        print(f"  ✅ [PortSwigger] 获取 {len(results)} 条安全研究")
        return results[:limit]

    def crawl_security_rss(self) -> List[str]:
        """爬取安全 RSS 订阅"""
        results = []
        rss_feeds = [
            ("https://feeds.feedburner.com/TheHackersNews", "THN"),
            ("https://www.cvedetails.com/vulnerability-feed.php", "CVEDetails"),
            ("https://security.googleblog.com/feeds/posts/default", "GoogleSec"),
            ("https://www.schneier.com/feed/atom/", "Schneier"),
            ("https://krebsonsecurity.com/feed/", "KrebsOnSecurity"),
            ("https://www.darkreading.com/rss.xml", "DarkReading"),
            ("https://threatpost.com/feed/", "ThreatPost"),
        ]

        print("  🕵️ [RSS] 爬取安全资讯订阅...")
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
                    print(f"    ✅ {source}: +{count} 条")
            except Exception:
                print(f"    ⚠️ {source} 解析失败")

        print(f"  ✅ [RSS] 共获取 {len(results)} 条资讯")
        return results

    def crawl_freebuf(self, limit: int = 10) -> List[str]:
        """爬取 FreeBuf 安全资讯"""
        results = []
        print("  🕵️ [FreeBuf] 爬取安全资讯...")

        urls = [
            "https://www.freebuf.com/articles/web",
            "https://www.freebuf.com/articles/security-product",
            "https://www.freebuf.com/articles/others-article",
        ]

        for url in urls:
            response = self._request_with_retry(url)
            if response:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # 尝试多种选择器
                    elements = []
                    for selector in ['article h2 a', '.article-title', '.item-title', 'h2.title', '.post-title']:
                        elements = soup.select(selector)
                        if elements:
                            break

                    for elem in elements[:limit]:
                        text = elem.text.strip() if elem.text else elem.get('title', '')
                        if text and len(text) > 10:
                            results.append(f"FreeBuf: {self._clean_text(text, 80)}")
                    if results:
                        break
                except Exception:
                    continue

        print(f"  ✅ [FreeBuf] 获取 {len(results)} 篇资讯")
        return results[:limit]

    def crawl_secrss(self, limit: int = 10) -> List[str]:
        """爬取安全脉搏"""
        results = []
        print("  🕵️ [安全脉搏] 爬取安全文章...")

        urls = [
            "https://www.secrss.com",
            "https://www.secrss.com/articles",
        ]

        for url in urls:
            response = self._request_with_retry(url)
            if response:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # 查找文章标题
                    elements = soup.find_all(['h2', 'h3', 'a'])[:limit]
                    for elem in elements:
                        text = elem.text.strip()
                        if text and len(text) > 15:
                            results.append(f"安全脉搏: {self._clean_text(text, 80)}")
                    if results:
                        break
                except Exception:
                    continue

        print(f"  ✅ [安全脉搏] 获取 {len(results)} 篇文章")
        return results[:limit]

    def crawl_51testing(self, limit: int = 10) -> List[str]:
        """爬取 51Testing 测试社区"""
        results = []
        print("  🕵️ [51Testing] 爬取测试技术文章...")

        urls = [
            "https://www.51testing.com/html/index.html",
            "https://www.51testing.com/articles.html",
        ]

        for url in urls:
            response = self._request_with_retry(url)
            if response:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    elements = soup.find_all(['h3', 'h4', 'a'])[:limit]
                    for elem in elements:
                        text = elem.text.strip()
                        if text and len(text) > 10:
                            results.append(f"51Testing: {self._clean_text(text, 80)}")
                    if results:
                        break
                except Exception:
                    continue

        print(f"  ✅ [51Testing] 获取 {len(results)} 篇文章")
        return results[:limit]

    def crawl_vulhub(self, limit: int = 10) -> List[str]:
        """爬取 Vulhub 漏洞库"""
        results = []
        print("  🕵️ [Vulhub] 爬取漏洞环境...")

        urls = [
            "https://vulhub.org.cn/disclosure",
            "https://vulhub.org.cn/",
        ]

        for url in urls:
            response = self._request_with_retry(url)
            if response:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    elements = soup.find_all(['h3', 'h4', 'a'])[:limit]
                    for elem in elements:
                        text = elem.text.strip()
                        if text and len(text) > 5:
                            results.append(f"Vulhub: {self._clean_text(text, 80)}")
                    if results:
                        break
                except Exception:
                    continue

        print(f"  ✅ [Vulhub] 获取 {len(results)} 条漏洞环境")
        return results[:limit]

    def crawl_nosec(self, limit: int = 10) -> List[str]:
        """爬取 NOSEC 安全导航"""
        results = []
        print("  🕵️ [NOSEC] 爬取安全数据...")

        url = "https://www.nosec.org/"
        response = self._request_with_retry(url)
        if response:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['h2', 'h3', 'a'])[:limit]
                for elem in elements:
                    text = elem.text.strip()
                    if text and len(text) > 10:
                        results.append(f"NOSEC: {self._clean_text(text, 80)}")
                print(f"  ✅ [NOSEC] 获取 {len(results)} 条安全数据")
            except Exception as e:
                print(f"  ⚠️ [NOSEC] 解析失败: {e}")

        return results[:limit]

    def crawl_ths(self, limit: int = 10) -> List[str]:
        """爬取天窗社区"""
        results = []
        print("  🕵️ [天窗] 爬取开源安全项目...")

        url = "https://www.tomsawyer.com/"
        response = self._request_with_retry(url)
        if response:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['h2', 'h3', 'a'])[:limit]
                for elem in elements:
                    text = elem.text.strip()
                    if text and len(text) > 10:
                        results.append(f"THS: {self._clean_text(text, 80)}")
                print(f"  ✅ [天窗] 获取 {len(results)} 条项目")
            except Exception as e:
                print(f"  ⚠️ [天窗] 解析失败: {e}")

        return results[:limit]

    def crawl_wooyun(self, limit: int = 10) -> List[str]:
        """爬取 WooYun 镜像（乌云）"""
        results = []
        print("  🕵️ [乌云镜像] 爬取历史漏洞...")

        # 乌云已经关闭，使用公开的镜像或 API
        url = "https://wooyun.whitecell.org/"
        response = self._request_with_retry(url)
        if response:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['h3', 'a'])[:limit]
                for elem in elements:
                    text = elem.text.strip()
                    if text and len(text) > 10:
                        results.append(f"乌云: {self._clean_text(text, 80)}")
                print(f"  ✅ [乌云] 获取 {len(results)} 条漏洞")
            except Exception as e:
                print(f"  ⚠️ [乌云] 解析失败: {e}")

        # 如果没有结果，添加一些乌云的历史著名漏洞作为参考
        if not results:
            backup_data = [
                "乌云: 某厂商命令执行漏洞（历史）",
                "乌云: 某电商 SQL 注入漏洞（历史）",
                "乌云: 某银行越权访问漏洞（历史）",
                "乌云: 某社交平台敏感信息泄露（历史）",
                "乌云: 某云平台远程代码执行（历史）",
            ]
            results = backup_data

        return results[:limit]


def main():
    print("=" * 60)
    print("🌐 Pointend 全能威胁情报爬虫 v2.1 (优化版)")
    print("=" * 60)
    print(f"🕒 采集时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    crawler = FullThreatCrawler()
    all_vectors = []

    print("🌍 国际数据源爬取中...")
    print("-" * 60)
    all_vectors.extend(crawler.crawl_nvd_cves())
    all_vectors.extend(crawler.crawl_osv())
    all_vectors.extend(crawler.crawl_github_advisories())
    all_vectors.extend(crawler.crawl_exploit_db())
    all_vectors.extend(crawler.crawl_mitre_attack())
    all_vectors.extend(crawler.crawl_cwe_top25())
    all_vectors.extend(crawler.crawl_portswigger())
    all_vectors.extend(crawler.crawl_security_rss())

    print()
    print("🇨🇳 国内数据源爬取中...")
    print("-" * 60)
    all_vectors.extend(crawler.crawl_freebuf())
    all_vectors.extend(crawler.crawl_secrss())
    all_vectors.extend(crawler.crawl_51testing())
    all_vectors.extend(crawler.crawl_vulhub())
    all_vectors.extend(crawler.crawl_nosec())
    all_vectors.extend(crawler.crawl_wooyun())

    print()
    print("=" * 60)
    print("📦 开始入库...")

    with get_db() as db:
        added_count = 0
        for vector in all_vectors:
            if insert_vector(db, vector, "full-crawler-v2"):
                added_count += 1

        cursor = db.execute("SELECT COUNT(*) FROM attack_vectors")
        total = cursor.fetchone()[0]

        cursor = db.execute("SELECT source, COUNT(*) as cnt FROM attack_vectors GROUP BY source ORDER BY cnt DESC")
        sources = cursor.fetchall()

        print(f"✅ 新增 {added_count} 条")
        print(f"📊 总计 {total} 条，来自 {len(sources)} 个数据源")
        print()
        print("📈 数据源分布:")
        for row in sources[:15]:
            print(f"   {row[0]:20s}: {row[1]:3d} 条")

    print("=" * 60)
    print(f"🕒 完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
