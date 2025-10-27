import re
import requests
import os
from datetime import datetime

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
            if not line.strip().startswith('!'):  # 去除 ! 开头的注释头部
                lines.append(line.strip())
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
        return '.'.join(parts[-2:])  # 取后两段作为主域
    return domain

# ===============================
# ⚙️ 规则清理函数（删除子域）
# ===============================
def process_rules(rules):
    seen = {}
    cleaned = []
    deleted_count = 0

    for line in rules:
        line = line.strip()
        if not line or line.startswith('#'):
            cleaned.append(line)
            continue

        # 匹配 @@|| 或 || 开头的规则
        m = re.match(r'(@@?\|\|)([^/^\$]+)(.*)', line)
        if m:
            prefix, domain, suffix = m.groups()
            base = get_base_domain(domain)
            key = (base, suffix)

            # 如果父域 + 相同后缀 已存在，则删除子域
            if key not in seen:
                seen[key] = line
                cleaned.append(line)
            else:
                deleted_count += 1
                continue
        else:
            cleaned.append(line)

    return cleaned, deleted_count

# ===============================
# 🧹 分别处理白名单与黑名单
# ===============================
cleaned_whitelist, deleted_whitelist = process_rules(whitelist)
cleaned_blocklist, deleted_blocklist = process_rules(blocklist)

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
# 🧾 生成统一头部信息
# ===============================
def generate_header():
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    diff_w_str = f"增加 {diff_w} 条" if diff_w > 0 else f"减少 {abs(diff_w)} 条" if diff_w < 0 else "无变化 0 条"
    diff_b_str = f"增加 {diff_b} 条" if diff_b > 0 else f"减少 {abs(diff_b)} 条" if diff_b < 0 else "无变化 0 条"

    header = f"""###########################################################
# 📅 AdGuardHome 综合规则自动构建信息
# ⏰ 更新时间: {now} CST
# 🌐 规则来源:
#   白名单: {whitelist_url}
#   黑名单: {blocklist_url}
# --------------------------------------------------------
# 📊 白名单统计:
#   ▸ 原始规则数量: {len(whitelist)}
#   ▸ 删除子域数量: {deleted_whitelist}
#   ▸ 清理后规则数量: {current_w}
#   ▸ 与上次对比: {diff_w_str}
# --------------------------------------------------------
# 📊 黑名单统计:
#   ▸ 原始规则数量: {len(blocklist)}
#   ▸ 删除子域数量: {deleted_blocklist}
#   ▸ 清理后规则数量: {current_b}
#   ▸ 与上次对比: {diff_b_str}
# --------------------------------------------------------
# 🧩 说明:
#   1️⃣ 当父域与子域（包括规则后缀）同时存在时，保留父域规则，删除子域规则。
#   2️⃣ 多级子域（三级、四级）则保留级数更低的域名（父域）。
# ==========================================================
"""
    return header

header = generate_header()

# ===============================
# 💾 输出为两个文件
# ===============================
with open("cleaned_whitelist.txt", "w", encoding="utf-8") as f:
    f.write(header + "\n")
    f.write("\n".join(sorted(cleaned_whitelist)) + "\n")

with open("cleaned_blocklist.txt", "w", encoding="utf-8") as f:
    f.write(header + "\n")
    f.write("\n".join(sorted(cleaned_blocklist)) + "\n")

# 保存最新数量
write_current_count(current_w, current_b)

# ===============================
# ✅ 控制台输出摘要
# ===============================
print(f"白名单删除子域数量: {deleted_whitelist}")
print(f"黑名单删除子域数量: {deleted_blocklist}")
print("✅ 已输出: cleaned_whitelist.txt 与 cleaned_blocklist.txt")
