import re
import requests
import os
from datetime import datetime, timedelta, timezone

# ===============================
# 🌐 白名单与黑名单地址
# ===============================
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

last_count_file = "last_count.txt"

# ===============================
# 📥 获取远程文件并清理无用行（去除!开头的头部信息）
# ===============================
def fetch_file(url):
    try:
        r = requests.get(url)
        r.raise_for_status()
        lines = []
        for line in r.text.splitlines():
            line = line.strip()
            if line and not line.startswith('!'):
                lines.append(line)
        return lines
    except requests.RequestException as e:
        print(f"获取文件失败: {e}")
        exit(1)

# 获取白名单与黑名单规则
whitelist = fetch_file(whitelist_url)
blocklist = fetch_file(blocklist_url)

# ===============================
# 🧩 提取主域函数（用于去除子域）
# ===============================
def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

# ===============================
# ⚙️ 规则清理函数（删除子域）
# ===============================
def process_rules(rules, allow_prefix="@@||", block_prefix="||"):
    seen = set()
    cleaned = []
    deleted_count = 0

    for line in rules:
        line = line.strip()
        if not line or line.startswith('#'):
            cleaned.append(line)
            continue

        # 匹配白名单或黑名单规则
        if line.startswith(allow_prefix):
            prefix = allow_prefix
            body = line[len(allow_prefix):]
        elif line.startswith(block_prefix):
            prefix = block_prefix
            body = line[len(block_prefix):]
        else:
            cleaned.append(line)
            continue

        # 提取域名部分（去掉 ^、/、$ 之后的内容）
        domain = re.split(r'[\^/\$]', body)[0].strip()
        if not domain:
            cleaned.append(line)
            continue

        base = get_base_domain(domain)
        if base not in seen:
            seen.add(base)
            cleaned.append(line)
        else:
            deleted_count += 1

    return cleaned, deleted_count

# ===============================
# 🧹 分别处理白名单与黑名单
# ===============================
cleaned_whitelist, deleted_whitelist = process_rules(whitelist, allow_prefix="@@||", block_prefix="||")
cleaned_blocklist, deleted_blocklist = process_rules(blocklist, allow_prefix="@@||", block_prefix="||")

# ===============================
# 📊 读取与保存上次统计数量
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

current_w = len(cleaned_whitelist)
current_b = len(cleaned_blocklist)
last_w, last_b = read_last_count()
diff_w = current_w - last_w
diff_b = current_b - last_b

# ===============================
# 🧾 生成头部信息（分开显示）
# ===============================
def generate_header(list_type, url, original_count, deleted_count, current_count, diff_count):
    # 使用北京时间（UTC+8）
    beijing_time = datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')

    diff_str = (
        f"增加 {diff_count} 条" if diff_count > 0 else
        f"减少 {abs(diff_count)} 条" if diff_count < 0 else "无变化 0 条"
    )

    header = f"""###########################################################
# 📅 AdGuardHome {list_type} 自动构建信息
# ⏰ 更新时间: {beijing_time} CST
# 🌐 规则来源: {url}
# --------------------------------------------------------
# 📊 统计信息:
#   ▸ 原始规则数量: {original_count}
#   ▸ 删除子域数量: {deleted_count}
#   ▸ 清理后规则数量: {current_count}
#   ▸ 与上次对比: {diff_str}
# --------------------------------------------------------
# 🧩 说明:
#   当父域与子域（包括规则后缀）同时存在时，保留父域规则。
#   多级子域（三级、四级）则保留级数更低的域名（父域）。
# ==========================================================
"""
    return header

header_whitelist = generate_header(
    "白名单", whitelist_url, len(whitelist), deleted_whitelist, current_w, diff_w
)

header_blocklist = generate_header(
    "黑名单", blocklist_url, len(blocklist), deleted_blocklist, current_b, diff_b
)

# ===============================
# 💾 输出为两个文件
# ===============================
with open("cleaned_whitelist.txt", "w", encoding="utf-8") as f:
    f.write(header_whitelist + "\n")
    f.write("\n".join(sorted(cleaned_whitelist)) + "\n")

with open("cleaned_blocklist.txt", "w", encoding="utf-8") as f:
    f.write(header_blocklist + "\n")
    f.write("\n".join(sorted(cleaned_blocklist)) + "\n")

write_current_count(current_w, current_b)

# ===============================
# ✅ 控制台输出摘要
# ===============================
print("✅ 构建完成！")
print(f"白名单清理后: {current_w} 条（删除 {deleted_whitelist} 条）")
print(f"黑名单清理后: {current_b} 条（删除 {deleted_blocklist} 条）")
print("输出文件: cleaned_whitelist.txt, cleaned_blocklist.txt")
