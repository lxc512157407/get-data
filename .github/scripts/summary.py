"""
📊 情报汇总报告 - 公开仓库专用
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from datetime import datetime
from simple_kb import get_db, get_stats


def main():
    print()
    print("=" * 60)
    print("📊 POINTEND THREAT INTELLIGENCE")
    print("=" * 60)
    print(f"🕒 采集时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()

    with get_db() as db:
        stats = get_stats(db)

        cursor = db.execute("""
        SELECT source, COUNT(*) as cnt
        FROM attack_vectors
        GROUP BY source
        ORDER BY cnt DESC
        """)

        print("📦 攻击向量库按来源分布:")
        print("-" * 40)
        for row in cursor:
            print(f"  {row[0]:18s} | {row[1]:4d} 条")

        print()
        print("=" * 60)
        print(f"📊 总计: {stats['total_vectors']} 个攻击向量")
        print("=" * 60)
        print()
        print("💡 这是公开数据采集器")
        print("🔒 完整攻击引擎 + 热力值 + 变异 + 测试在本地运行")
        print("🌙 每晚同步到私有主仓库")
        print("=" * 60)

    with open("UPDATE_LOG.txt", "a", encoding="utf-8") as f:
        f.write(f"\n{datetime.now().strftime('%Y-%m-%d %H:%M')} | 总计 {stats['total_vectors']} 向量")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
