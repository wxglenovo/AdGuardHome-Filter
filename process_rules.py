
import re
import requests
from datetime import datetime

# ==========================================================
# 📌 规则来源
# ==========================================================
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

# ==========================================================
# 📌 下载规则文件
# ==========================================================
def download_rules(url):
    print(f"📥 正在下载: {url}")
    resp = requests.get(url, timeout=60)
    resp.encoding = 'utf-8'
    lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
    return lines

# ==========================================================
# 📌 提取域名与规则后缀
# ==========================================================
def extract_domain_and_suffix(rule):
    match = re.match(r'(@@)?\|\|([^/^$]+)(.*)', rule)
    if match:
        prefix = match.group(1) or ''
        domain = match.group(2).strip('.')
        suffix = match.group(3)
        return prefix, domain, suffix
    return '', '', ''

# ==========================================================
# 📌 判断是否为子域
# ==========================================================
def is_subdomain(child, parent):
    return child.endswith('.' + parent)

# ==========================================================
# 📌 清理逻辑：删除父域 + 子域重复项
# ==========================================================
def clean_rules(rules):
    parsed = []
    for rule in rules:
        prefix, domain, suffix = extract_domain_and_suffix(rule)
        if domain:
            parsed.append((prefix, domain, suffix, rule))

    # 按域名级数排序（低级在前）
    parsed.sort(key=lambda x: x[1].count('.'))
    skip = set()

    for i, (prefix_i, domain_i, suffix_i, rule_i) in enumerate(parsed):
        if rule_i in skip:
            continue
        for j, (prefix_j, domain_j, suffix_j, rule_j) in enumerate(parsed):
            if i != j and rule_j not in skip:
                # 删除子域（前缀和后缀完全一致时）
                if is_subdomain(domain_j, domain_i) and suffix_i == suffix_j and prefix_i == prefix_j:
                    skip.add(rule_j)

    cleaned = [rule for _, _, _, rule in parsed if rule not in skip]
    return cleaned, len(skip)

# ==========================================================
# 📌 生成头部信息（无 “!” 内容）
# ==========================================================
def build_header(stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S CST")
    header = f"""###########################################################
# 📅 AdGuardHome 综合规则自动构建信息
# ⏰ 更新时间: {now}
# 🌐 规则来源:
#   白名单: {whitelist_url}
#   黑名单: {blocklist_url}
# --------------------------------------------------------
# 白名单原始规则数量: {stats['white_total']}
# 白名单删除子域数量: {stats['white_removed']}
# 白名单清理后规则数量: {stats['white_final']}
# --------------------------------------------------------
# 黑名单原始规则数量: {stats['black_total']}
# 黑名单删除子域数量: {stats['black_removed']}
# 黑名单清理后规则数量: {stats['black_final']}
# --------------------------------------------------------
# 说明:
#   当父域与子域（包括规则后缀）同时存在时，保留父域规则，删除子域规则。
#   多级子域（三级、四级）则保留级数更低的域名（父域）。
# ==========================================================
"""
    return header

# ==========================================================
# 📌 主执行逻辑
# ==========================================================
def main():
    print("📥 开始下载规则文件...")
    whitelist = download_rules(whitelist_url)
    blocklist = download_rules(blocklist_url)

    print("🧹 清理白名单...")
    cleaned_white, removed_white = clean_rules(whitelist)

    print("🧹 清理黑名单...")
    cleaned_black, removed_black = clean_rules(blocklist)

    stats = {
        "white_total": len(whitelist),
        "white_removed": removed_white,
        "white_final": len(cleaned_white),
        "black_total": len(blocklist),
        "black_removed": removed_black,
        "black_final": len(cleaned_black),
    }

    header = build_header(stats)
    all_rules = cleaned_white + cleaned_black
    output = header + "\n".join(all_rules) + "\n"

    with open("AdGuardHome_Filter.txt", "w", encoding="utf-8") as f:
        f.write(output)

    print("✅ 规则构建完成 → AdGuardHome_Filter.txt")

# ==========================================================
if __name__ == "__main__":
    main()
