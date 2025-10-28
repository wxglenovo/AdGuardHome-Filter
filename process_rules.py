import re
import requests
from datetime import datetime, timedelta

# -----------------------------
# 配置区
# -----------------------------
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blacklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

def fetch_rules(url):
    print(f"📥 正在下载规则: {url}")
    resp = requests.get(url)
    resp.encoding = 'utf-8'
    lines = resp.text.splitlines()
    # 去掉注释行和无效行
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith('!') and not l.strip().startswith('#')]

def extract_domain(rule):
    """提取纯域名（不包含@@||、||和^）"""
    rule = rule.replace('@@||', '').replace('||', '')
    rule = rule.split('^')[0].strip()
    return rule.lower()

def is_subdomain(sub, parent):
    """严格判断 sub 是否是 parent 的子域（即 sub = xxx.parent）"""
    return sub.endswith("." + parent)

def clean_rules(rules, is_whitelist=False):
    print("\n🧹 正在清理规则...")
    cleaned = []
    removed = []
    domains = [extract_domain(r) for r in rules]

    # 保留原规则符号
    prefix = "@@||" if is_whitelist else "||"

    for i, r in enumerate(rules):
        domain = domains[i]
        # 检查是否有父域存在
        has_parent = False
        for p in domains:
            if domain != p and is_subdomain(domain, p):
                has_parent = True
                removed.append((r, f"{prefix}{p}^"))
                break
        if not has_parent:
            cleaned.append(r)

    # 日志
    if removed:
        print("🗑 删除的匹配项（子域 -> 父域）：")
        for child, parent in removed:
            print(f"   ❌ {child} → 保留 {parent}")
    else:
        print("✅ 无匹配项删除。")

    print(f"✅ 原始规则: {len(rules)} | 删除子域: {len(removed)} | 清理后: {len(cleaned)}")
    return cleaned, removed

def save_file(filename, rules, removed, is_whitelist):
    tz = timedelta(hours=8)
    now = datetime.utcnow() + tz
    header = [
        f"# {'白名单' if is_whitelist else '黑名单'}规则",
        f"# 更新时间: {now.strftime('%Y-%m-%d %H:%M:%S')} CST",
        f"# 原始规则数量: {len(rules) + len(removed)}",
        f"# 删除子域数量: {len(removed)}",
        f"# 清理后规则数量: {len(rules)}",
        "# ==========================================================",
        ""
    ]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(header + rules))
    print(f"💾 已保存文件: {filename}\n")

# -----------------------------
# 主流程
# -----------------------------
def main():
    whitelist = fetch_rules(whitelist_url)
    blacklist = fetch_rules(blacklist_url)

    cleaned_white, removed_white = clean_rules(whitelist, is_whitelist=True)
    cleaned_black, removed_black = clean_rules(blacklist, is_whitelist=False)

    save_file("cleaned_whitelist.txt", cleaned_white, removed_white, is_whitelist=True)
    save_file("cleaned_blacklist.txt", cleaned_black, removed_black, is_whitelist=False)

    print("🎉 清理完成！输出文件：cleaned_whitelist.txt、cleaned_blacklist.txt")

if __name__ == "__main__":
    main()
