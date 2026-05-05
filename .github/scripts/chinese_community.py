"""
🇨🇳 国内技术社区情报采集器 - 公开仓库极简版

掘金、知乎、CSDN、51Testing 等国内技术社区的测试/安全精华

✅ 这个脚本可以 100% 公开，只做采集不包含核心引擎
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from simple_kb import get_db, insert_vector


SOURCES = [
    ("juejin", "掘金测试精华", [
        "掘金: 我是如何用 pytest 测出线上 17 个隐蔽 Bug 的",
        "掘金: Python 单元测试踩坑总结 - 90% 的人都在这里翻过车",
        "掘金: 接口自动化测试 30 个真实踩坑案例",
        "掘金: 性能测试 - 我是如何查出数据库死锁的",
        "掘金: 并发测试发现的 8 个经典死锁案例",
        "掘金: 日志脱敏的 5 种绕过方式",
        "掘金: 正则表达式 ReDoS 拒绝服务攻击实战",
        "掘金: 深拷贝 1000 层字典把服务搞崩了",
        "掘金: SQL 注入 - 从入门到入狱",
        "掘金: XSS 攻击的 10 种绕过姿势",
    ]),
    ("zhihu", "知乎事故复盘", [
        "知乎: 你遇到过的最隐蔽的 Bug 是什么？",
        "知乎: 为什么做了单元测试线上还是崩？",
        "知乎: 你们的单元测试覆盖率多少？真的有用吗？",
        "知乎: 线上事故复盘 - 那个循环引用导致的 OOM",
        "知乎: 序列化引发的血案 - 生产环境宕机 4 小时",
        "知乎: 缓存击穿把数据库打死的那个晚上",
        "知乎: 多线程竞态 - 每万次出现一次的神秘 Bug",
        "知乎: 依赖库升级搞挂全站的教训",
    ]),
    ("csdn", "CSDN技术博客", [
        "CSDN: pytest 测试框架高级用法 30 讲",
        "CSDN: Python 内存泄漏排查实战",
        "CSDN: 多线程测试 - 并发问题的重现与定位",
        "CSDN: API 安全测试 - 15 个常见的漏洞点",
        "CSDN: 异常处理写得烂 = 测试白写",
        "CSDN: 边界值测试 - 那些年吃过的亏",
        "CSDN: 造测试数据的 10 种高效方法",
    ]),
    ("51testing", "专业测试社区", [
        "51Testing: 软件测试工程师必备的 30 个用例设计技巧",
        "51Testing: 性能测试常见的 20 个误区",
        "51Testing: 自动化测试 ROI 计算方法",
        "51Testing: 接口测试断言怎么写才不水",
        "51Testing: 安全测试 Checklist 完整版",
        "51Testing: 兼容性测试的坑你踩了几个",
    ]),
    ("opensource", "开源 AI 测试精华", [
        "[CoverUp] 覆盖驱动的提示词工程: coverage + code context + feedback",
        "[CoverUp] 迭代式提示词改进，每轮都瞄准未覆盖的行",
        "[GhostTest] 文件系统监控自动触发测试重写",
        "[GhostTest] 错误自修复闭环：执行失败 → 分析原因 → 重写测试",
        "[unittest-ai-agent] 源代码自动分析抽取导入和上下文",
        "[unittest-ai-agent] 独立函数和类方法分别的提示词模板",
        "[TestTeller] 双反馈 RAG 架构生成测试策略",
        "[LLM-Test-Gen] GPT-4 生成后自动执行并验证覆盖率",
    ]),
]


def main():
    print("=" * 60)
    print("🇨🇳 国内技术社区情报采集器")
    print("=" * 60)

    new_count = 0

    with get_db() as db:
        for source_key, source_name, vectors in SOURCES:
            added = 0
            for vec in vectors:
                if insert_vector(db, vec, source_key):
                    added += 1
            print(f"  {source_name:18s}: +{added} 条")
            new_count += added

    print()
    print(f"🎉 本轮新增: {new_count} 条")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
