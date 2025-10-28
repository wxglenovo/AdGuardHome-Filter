import re
import requests
import os
from datetime import datetime, timedelta

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
            if not line or line.startswith('!'):
                continue
            lines.append(line)
        return lines
    except requests.RequestException as e:
        print(f"❌ 获取文件失败: {e}")
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
# ⚙️ 规则清理函数（删除子域，区分前缀）
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
            key = (prefix, base, suffix)  # ✅ 加入 prefix 区分白/黑名单类型

            # 判断是否是父域 + 相同后缀（例如 baidu.com 与 www.baidu.com）
            if key not in seen:
                seen[key] = line
                cleaned.append(line)
            else:
                deleted_count += 1
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
# 🧾 生成各自头部信息
# ===============================
def generate_header(list_type, original_count, deleted_count, current_count, diff, url):
    now = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')  # 北京时间
    diff_str = f"增加 {diff} 条" if diff > 0 else f"减少 {abs(diff)} 条" if diff < 0 else "无变化 0 条"

    header = f"""###########################################################
# 📅 AdGuardHome {list_type} 自动构建信息
# ⏰ 更新时间: {now} CST
# 🌐 规则来源: {url}
# --------------------------------------------------------
# 原始规则数量: {original_count}
# 删除子域数量: {deleted_count}
# 清理后规则数量: {current_count}
# 与上次对比: {diff_str}
# --------------------------------------------------------
# 🧩 说明:
#   ▸ 当父域与子域（包括规则后缀）同时存在时，保留父域规则，删除子域规则。
#   ▸ 多级子域（三级、四级）则保留级数更低的域名（父域）。
# ==========================================================
"""
    return header

# ===============================
# 💾 输出为两个文件
# ===============================
header_w = generate_header("白名单", len(whitelist), deleted_whitelist, current_w, diff_w, whitelist_url)
header_b = generate_header("黑名单", len(blocklist), deleted_blocklist, current_b, diff_b, blocklist_url)

with open("cleaned_whitelist.txt", "w", encoding="utf-8") as f:
    f.write(header_w + "\n")
    f.write("\n".join(sorted(cleaned_whitelist)) + "\n")

with open("cleaned_blocklist.txt", "w", encoding="utf-8") as f:
    f.write(header_b + "\n")
    f.write("\n".join(sorted(cleaned_blocklist)) + "\n")

# 保存最新数量
write_current_count(current_w, current_b)

# ===============================
# ✅ 控制台输出摘要
# ===============================
print("✅ 白名单与黑名单处理完成")
print(f"📊 白名单 删除子域数量: {deleted_whitelist}")
print(f"📊 黑名单 删除子域数量: {deleted_blocklist}")
print("📄 已输出文件: cleaned_whitelist.txt 与 cleaned_blocklist.txt")
