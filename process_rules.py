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
    # 去掉注释行、空行、以“!”或“#”开头的头部信息
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith(('!', '#'))]

def extract_domain_and_suffix(rule):
    """
    提取域名与后缀部分（不移除后缀）
    返回 (域名, 后缀)
    如 @@||a.b.c.com^$domain=x.y → ('a.b.c.com', '^$domain=x.y')
    """
    rule_body = rule
    rule_body = rule_body.replace('@@||', '').replace('||', '')
    if '^' in rule_body:
        domain, suffix = rule_body.split('^', 1)
        suffix = '^' + suffix
    else:
        domain, suffix = rule_body, ''
    return domain.lower().strip(), suffix.strip()

def is_subdomain(sub, parent):
    """判断 sub 是否是 parent 的子域，例如 sub = a.b.com, parent = b.com"""
    return sub.endswith("." + parent)

def clean_rules(rules, is_whitelist=False):
    print(f"\n🧹 正在清理 {'白名单' if is_whitelist else '黑名单'}...")
    cleaned = []
    removed = []

    prefix = "@@||" if is_whitelist else "||"

    parsed = [extract_domain_and_suffix(r) for r in rules]

    for i, (domain, suffix) in enumerate(parsed):
        has_parent = False
        for j, (pdomain, psuffix) in enumerate(parsed):
            if i != j and is_subdomain(domain, pdomain) and suffix == psuffix:
                # 子域与父域后缀完全相同，才算匹配
                has_parent = True
                removed.append((rules[i], f"{prefix}{pdomain}{psuffix}"))
                break
        if not has_parent:
            cleaned.append(rules[i])

    # 输出日志
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
