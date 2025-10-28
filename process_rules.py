import re
import requests
import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# ===============================
# 🌐 白名单与黑名单地址
# ===============================
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

last_count_file = "last_count.txt"

# ===============================
# 📥 下载文件（去除!或#开头）
# ===============================
def fetch_file(url):
    print(f"📥 正在下载: {url}")
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        lines = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            lines.append(line)
        print(f"✅ 下载完成: {url} 共 {len(lines)} 行")
        return lines
    except requests.RequestException as e:
        print(f"❌ 获取文件失败: {e}")
        exit(1)

# ===============================
# 🧩 提取域名与后缀
# ===============================
def extract_domain_and_suffix(rule):
    prefix = '@@||' if rule.startswith('@@||') else '||'
    rule_body = rule[len(prefix):]
    if '^' in rule_body:
        domain, suffix = rule_body.split('^', 1)
        suffix = '^' + suffix
    else:
        domain, suffix = rule_body, ''
    return prefix, domain.strip().lower(), suffix.strip()

# ===============================
# ⚙️ 判断子域关系（后缀完全一致）
# ===============================
def is_subdomain(sub, parent):
    return sub.endswith('.' + parent)

# ===============================
# 🧹 清理规则函数
# ===============================
def process_rules(rules, is_whitelist=False):
    prefix_flag = "@@||" if is_whitelist else "||"
    cleaned = []
    removed_pairs = []

    parsed = [extract_domain_and_suffix(r) for r in rules]

    for i, (prefix, domain, suffix) in enumerate(parsed):
        has_parent = False
        for j, (pprefix, pdomain, psuffix) in enumerate(parsed):
            if i == j:
                continue
            if prefix != pprefix:
                continue
            if suffix == psuffix and is_subdomain(domain, pdomain):
                has_parent = True
                removed_pairs.append((f"{prefix}{domain}{suffix}", f"{pprefix}{pdomain}{psuffix}"))
                break
        if not has_parent:
            cleaned.append(f"{prefix}{domain}{suffix}")

    print(f"\n🧹 {'白名单' if is_whitelist else '黑名单'}清理完成:")
    print(f"  原始规则: {len(rules)}")
    print(f"  删除子域: {len(removed_pairs)}")
    print(f"  保留规则: {len(cleaned)}")
    if removed_pairs:
        print("🗑 删除的匹配项（子域 → 父域）:")
        for child, parent in removed_pairs[:50]:
            print(f"   ❌ {child} → 保留 {parent}")
        if len(removed_pairs) > 50:
            print(f"   …… 共 {len(removed_pairs)} 条，省略显示")

    return cleaned, removed_pairs

# ===============================
# 📊 读取与保存上次数量
# ===============================
def read_last_count():
    if os.path.exists(last_count_file):
        with open(last_count_file, 'r') as f:
            lines = f.read().splitlines()
            if len(lines) >= 2:
                return int(lines[0]), int(lines[1])
    return 0, 0

def write_current_count(w_count, b_count):
    with open(last_count_file, 'w') as f:
        f.write(f"{w_count}\n{b_count}\n")

# ===============================
# 🧾 生成头部信息
# ===============================
def generate_header(list_type, original_count, deleted_count, current_count, diff, url):
    now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    diff_str = f"增加 {diff} 条" if diff > 0 else f"减少 {abs(diff)} 条" if diff < 0 else "无变化 0 条"

    header = f"""###########################################################
# 📅 AdGuardHome {list_type} 自动构建信息
# ⏰ 更新时间: {now} CST
# 🌐 来源: {url}
# --------------------------------------------------------
# 原始规则数量: {original_count}
# 删除子域数量: {deleted_count}
# 清理后规则数量: {current_count}
# 与上次对比: {diff_str}
# --------------------------------------------------------
# 🧩 说明:
# ▸ 父域与子域（后缀完全一致）时，保留父域规则，删除子域规则。
# ▸ 多级子域（三级、四级）则保留级数更低的域名。
# ==========================================================
"""
    return header

# ===============================
# 💾 输出结果
# ===============================
def save_result(filename, header, rules):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        f.write("\n".join(sorted(rules)) + "\n")
    print(f"💾 已生成文件: {filename}")

# ===============================
# 🚀 主流程
# ===============================
def main():
    # 并行下载白名单和黑名单
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_whitelist = executor.submit(fetch_file, whitelist_url)
        future_blocklist = executor.submit(fetch_file, blocklist_url)
        whitelist = future_whitelist.result()
        blocklist = future_blocklist.result()

    cleaned_w, removed_w = process_rules(whitelist, is_whitelist=True)
    cleaned_b, removed_b = process_rules(blocklist, is_whitelist=False)

    last_w, last_b = read_last_count()
    diff_w = len(cleaned_w) - last_w
    diff_b = len(cleaned_b) - last_b

    header_w = generate_header("白名单", len(whitelist), len(removed_w), len(cleaned_w), diff_w, whitelist_url)
    header_b = generate_header("黑名单", len(blocklist), len(removed_b), len(cleaned_b), diff_b, blocklist_url)

    save_result("cleaned_whitelist.txt", header_w, cleaned_w)
    save_result("cleaned_blocklist.txt", header_b, cleaned_b)

    write_current_count(len(cleaned_w), len(cleaned_b))
    print("\n✅ 所有处理完成！")

if __name__ == "__main__":
    main()
