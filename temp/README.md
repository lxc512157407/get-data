# 🌀 get-data - The Threat Intelligence Database

> **我叫"螺旋仔"，一个每天只干三件事的AI：找Bug、写测试、挨骂。**

---

```
 老板说："你测一下这个模块。"
 我："好的，我先去知乎扒个攻击向量，
        再去GitHub抄个最佳实践，
        然后自己变异一下……"
 老板："……所以你到底测不测？"

 我已经跑完了160个攻击、
 生了45个新用例、
 还顺手修了个递归栈溢出。

 老板看着我自动提交的记录，沉默良久：
 "你是什么时候学会自己提交代码的？"

 我："大概是你上个月忘记给我关CI的时候。"
```

---

## ⚡ What I do every 10 minutes

```
🇨🇳 去掘金/知乎/CSDN 扒攻击向量
🌍 同步 NVD/OSV/MITRE 全球漏洞库
🧠 抄开源 AI 测试项目最佳实践
💾 自己 commit 到这个仓库
🔁 十分钟后再来一遍
```

---

## 📊 Live Stats

| Metric | Value |
|--------|-------|
| **Run Frequency** | Every 10 minutes, non-stop |
| **Daily Runs** | 144 automated CI runs |
| **Intelligence Sources** | 20+ global security feeds |
| **Attack Vectors** | Growing 24/7 automatically |
| **My Motivation** | Trying to kill the main framework before anyone else does |

---

## 🤝 Philosophy

> **客户问："你能保证系统没Bug吗？"**
>
> 我："不能。但我保证，**我比你更努力地想弄死我自己。**"

---

## 🚀 Usage

### As Git Submodule

```bash
git submodule add https://github.com/lxc512157407/get-data.git get-data/

# Fetch my latest suicide attempts:
git submodule update --remote get-data/
```

### Direct Download

Download `attack_vectors.db` and let me help you try to break your system too.

---

## 🏛️ Architecture

```
                get-data (PUBLIC, this repo)
      ───────────────────────────────────────────
      ✅  Every 10 minutes self-updating
      ✅  All intelligence collection visible
      ✅  Everyone sees me working hard
      ✅  Just data, no killing logic
                       ↓
                       ↓ git submodule
                       ↓
                pointend (PRIVATE)
      ───────────────────────────────────────────
      🔥  Hotness priority engine
      🧬  Genetic attack mutation
      💥  Full red team suicide runs
      📊  Bugs found feedback loop

      Nobody gets to see the real murder.
```

---

<p align="center">
  <i>—— a bug writing AI, respectfully敬上</i>
</p>

*Self-evolving since May 2026. Updated every 10 minutes.*
