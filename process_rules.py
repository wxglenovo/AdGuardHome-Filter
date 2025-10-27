import re
import requests
import os
from datetime import datetime

# ==========================================================
# 白名单和黑名单源地址
# ==========================================================
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'
last_count_file = "last_count.txt"
# ==========================================================

def fetch_file(url):
    """获取远程规则文件"""
    try:
        r = requests.get(url)
        r.raise_for_status()
        return r.text.splitlines()
    except requests.RequestException as e:
        print(f"❌ 获取文件失败: {e}")
        exit(1)

# 获取规则内容
whitelist = fetch_file(whitelist_url)
blocklist = fetch_file(blocklist_url)

def get_base_domain(domain):
    """提取主域（例如 a.b.example.com -> example.com）"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def process_rules(rules):
    """根据父域+后缀去重，只保留父域规则"""
    seen = {}
    cleaned = []
    deleted_count = 0

    for line in rules:
        line = line.strip()
        if not line or line.startswith('#'):
            cleaned.append(line)
            continue

        # 匹配 || 或 @@|| 开头的域名规则
        m = re.match(r'(@@?\|\|)([^/^\$]+)(.*)', line)
        if m:
            prefix, domain, suffix = m.groups()
            base = get_base_domain(domain)
            key = (base, suffix)

            if key not in seen:
                seen[key] = line
                cleaned.append(line)
            else:
                deleted_count += 1
        else:
            cleaned.append(line)

    return cleaned, deleted_count


# 执行白名单和黑名单去重
cleaned_whitelist, deleted_whitelist = process_rules(whitelist)
cleaned_blocklist, deleted_blocklist = process_rules(blocklist)

# ==========================================================
# 读取与写入历史记录
# ==========================================================
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

current_w = len(cleaned_whitelist)
current_b = len(cleaned_blocklist)
last_w, last_b = read_last_count()
diff_w = current_w - last_w
diff_b = current_b - last_b
write_current_count(current_w, current_b)
# ==========================================================


# ==========================================================
# 统一头部信息（白名单 + 黑名单整合显示）
# ==========================================================
header = [
    "###########################################################",
    "# 📅 AdGuardHome 综合规则自动构建信息",
    f"# ⏰ 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "# 🌐 规则来源:",
    f"#   白名单: {whitelist_url}",
    f"#   黑名单: {blocklist_url}",
    "# --------------------------------------------------------",
    f"# 白名单原始规则数量: {len(whitelist)}",
    f"# 白名单删除子域数量: {deleted_whitelist}",
    f"# 白名单清理后规则数量: {current_w}",
    f"# 白名单与上次对比: {('增加' if diff_w>0 else '减少' if diff_w<0 else '无变化')} {abs(diff_w)} 条",
    "# --------------------------------------------------------",
    f"# 黑名单原始规则数量: {len(blocklist)}",
    f"# 黑名单删除子域数量: {deleted_blocklist}",
    f"# 黑名单清理后规则数量: {current_b}",
    f"# 黑名单与上次对比: {('增加' if diff_b>0 else '减少' if diff_b<0 else '无变化')} {abs(diff_b)} 条",
    "# --------------------------------------------------------",
    "# 说明: 当父域与子域（包括规则后缀）同时存在时，保留父域规则，删除子域规则。",
    "# 多级子域（三级、四级）则保留级数更低的域名（父域）。",
    "# ==========================================================",
    ""
]

# ==========================================================
# 输出结果文件
# ==========================================================
def write_file(filename, header, rules):
    with open(filename, "w", encoding="utf-8") as f:
        f.write('\n'.join(header))
        f.write('\n'.join(sorted(rules)) + '\n')

write_file("cleaned_whitelist.txt", header, cleaned_whitelist)
write_file("cleaned_blocklist.txt", header, cleaned_blocklist)

print("✅ 白名单与黑名单已清理完毕，并生成统一头部信息。")
