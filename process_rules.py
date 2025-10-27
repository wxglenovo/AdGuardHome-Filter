import re
import requests
import os
from datetime import datetime

###########################################################
# 📅 AdGuardHome 综合规则自动构建信息
# 🌐 来源:
#   白名单: https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt
#   黑名单: https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt
# ==========================================================
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'
last_count_file = "last_count.txt"


def fetch_file(url):
    """从远程URL获取文件，并去掉以!开头的注释行"""
    try:
        r = requests.get(url)
        r.raise_for_status()
        lines = r.text.splitlines()
        # 去掉空行、以!开头的注释行
        lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('!')]
        return lines
    except requests.RequestException as e:
        print(f"❌ 获取文件失败: {e}")
        exit(1)


# 获取规则（自动清理!头部）
whitelist = fetch_file(whitelist_url)
blocklist = fetch_file(blocklist_url)


def get_base_domain(domain):
    """提取主域（例如 sub.baidu.com → baidu.com）"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def process_rules(rules):
    """去重 + 删除子域规则"""
    seen = {}
    cleaned = []
    deleted_count = 0

    for line in rules:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # 匹配 || 或 @@|| 开头规则
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


# 处理白名单和黑名单
cleaned_whitelist, deleted_whitelist = process_rules(whitelist)
cleaned_blocklist, deleted_blocklist = process_rules(blocklist)


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


def combined_header():
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f"""###########################################################
# 📅 AdGuardHome 综合规则自动构建信息
# ⏰ 更新时间: {now}
# 🌐 规则来源:
#   白名单: {whitelist_url}
#   黑名单: {blocklist_url}
# --------------------------------------------------------
# 白名单原始规则数量: {len(whitelist)}
# 白名单删除子域数量: {deleted_whitelist}
# 白名单清理后规则数量: {current_w}
# 白名单与上次对比: {('增加' if diff_w>0 else '减少') if diff_w!=0 else '无变化'} {abs(diff_w)} 条
# --------------------------------------------------------
# 黑名单原始规则数量: {len(blocklist)}
# 黑名单删除子域数量: {deleted_blocklist}
# 黑名单清理后规则数量: {current_b}
# 黑名单与上次对比: {('增加' if diff_b>0 else '减少') if diff_b!=0 else '无变化'} {abs(diff_b)} 条
# --------------------------------------------------------
# 说明: 当父域与子域（包括规则后缀）同时存在时，保留父域规则，删除子域规则。
# 多级子域（三级、四级）则保留级数更低的域名（父域）。
# ==========================================================
"""


# 输出整合后的文件
with open("cleaned_rules.txt", "w", encoding="utf-8") as f:
    f.write(combined_header() + "\n")
    f.write("# ======= 白名单 =======\n")
    f.write('\n'.join(sorted(cleaned_whitelist)) + "\n\n")
    f.write("# ======= 黑名单 =======\n")
    f.write('\n'.join(sorted(cleaned_blocklist)) + "\n")

write_current_count(current_w, current_b)

print("✅ 已生成 cleaned_rules.txt")
print(f"白名单删除子域数量: {deleted_whitelist}")
print(f"黑名单删除子域数量: {deleted_blocklist}")
