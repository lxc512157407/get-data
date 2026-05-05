# get-data: Threat Intelligence Database

Automated threat intelligence collection for security testing frameworks.

---

## Features

- **Continuous Collection**: Automated updates every 10 minutes via GitHub Actions
- **Multi-source Intelligence**: Aggregates from 20+ public security feeds
- **Standardized Format**: SQLite database for easy integration
- **Open Data**: CC0 licensed, free for any security project to use

---

## Intelligence Sources

| Category | Sources |
|----------|---------|
| **Domestic Tech** | Juejin, Zhihu, CSDN, 51Testing |
| **Global CVE** | NVD, OSV, MITRE, Exploit-DB |
| **Web Security** | PortSwigger, OWASP |
| **Best Practices** | Open source testing projects |

---

## Usage

### As Git Submodule

```bash
git submodule add https://github.com/lxc512157407/get-data.git get-data/

# Update to latest intelligence:
git submodule update --remote get-data/
```

### Direct Access

Download `attack_vectors.db` and integrate with your testing pipeline.

---

## Database Schema

```sql
CREATE TABLE attack_vectors (
    id INTEGER PRIMARY KEY,
    title TEXT UNIQUE,
    source TEXT,
    category TEXT,
    created_at TEXT,
    collected_at TEXT
)
```

---

## Automated Updates

This repository uses GitHub Actions to:
1. Fetch latest intelligence from all configured sources
2. Deduplicate and normalize entries
3. Commit and push updated database
4. Log changes for audit trail

---

## License

Data in this repository is released under CC0 1.0 Universal.
