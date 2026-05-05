"""
🌍 全球威胁情报网络 - 公开仓库极简版

NVD / OSV / Exploit-DB / PortSwigger / MITRE

✅ 这个脚本可以 100% 公开，只做采集不包含核心引擎
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from simple_kb import get_db, insert_vector


GLOBAL_SOURCES = [
    ("nvd", "NVD 国家漏洞数据库", [
        "NVD-CWE-787: Out-of-bounds Write",
        "NVD-CWE-79: Cross-site Scripting",
        "NVD-CWE-89: SQL Injection",
        "NVD-CWE-416: Use After Free",
        "NVD-CWE-78: OS Command Injection",
        "NVD-CWE-20: Improper Input Validation",
        "NVD-CWE-22: Path Traversal",
        "NVD-CWE-352: Cross-Site Request Forgery",
        "NVD-CWE-434: Unrestricted File Upload",
        "NVD-CWE-918: Server-Side Request Forgery",
    ]),
    ("osv", "OSV 开源漏洞库", [
        "OSV: Python ecosystem vulnerabilities",
        "OSV: PyPI package vulnerabilities",
        "OSV: Supply chain attack vectors",
        "OSV: Dependency confusion attacks",
        "OSV: Typosquatting package detection",
    ]),
    ("exploit-db", "Exploit-DB", [
        "Exploit-DB: Web application attacks",
        "Exploit-DB: Local privilege escalation",
        "Exploit-DB: Remote code execution",
        "Exploit-DB: Authentication bypasses",
        "Exploit-DB: Injection techniques",
    ]),
    ("portswigger", "PortSwigger Web Security", [
        "PortSwigger: SQL injection cheat sheet",
        "PortSwigger: XSS filter evasion",
        "PortSwigger: CSRF techniques",
        "PortSwigger: Clickjacking attacks",
        "PortSwigger: CORS misconfigurations",
    ]),
    ("mitre", "MITRE ATT&CK", [
        "MITRE: Initial access vectors",
        "MITRE: Execution techniques",
        "MITRE: Persistence mechanisms",
        "MITRE: Privilege escalation",
        "MITRE: Defense evasion",
    ]),
    ("cwe-top25", "MITRE CWE Top 25", [
        "CWE-787: Out-of-bounds Write",
        "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "CWE-416: Use After Free",
        "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "CWE-20: Improper Input Validation",
        "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        "CWE-352: Cross-Site Request Forgery",
        "CWE-434: Unrestricted Upload of File with Dangerous Type",
        "CWE-918: Server-Side Request Forgery",
    ]),
]


def main():
    print("=" * 60)
    print("🌍 全球威胁情报网络")
    print("=" * 60)

    new_count = 0

    with get_db() as db:
        for source_key, source_name, vectors in GLOBAL_SOURCES:
            added = 0
            for vec in vectors:
                if insert_vector(db, vec, source_key):
                    added += 1
            print(f"  {source_name:28s}: +{added} 条")
            new_count += added

    print()
    print(f"🎉 本轮新增: {new_count} 条")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
