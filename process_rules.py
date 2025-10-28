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
        print(f"❌ 获取文件失败: {e}")
        exit(1)

# 获取白名单与黑名单规则
whitelist = fetch_file(whitelist_url)
blocklist = fetch_file(blocklist_url)

# ===============================
# 🧩 提取主域函数
# ===============================
def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

# ===============================
# ⚙️ 规则清理函数（包括后缀匹配 + 日志输出）
# ===============================
def process_rules(rules, prefix, list_name):
    cleaned = []
    keep_dict = {}  # 记录父域 + 后缀
    parsed_rules = []

    # 预解析规则
    for line in rules:
        if not line.startswith(prefix):
            continue
        body = line[len(prefix):]
        match = re.match(r"([^/^\$]+)([\/\^\$].*)?$", body)
        if not match:
            continue
        domain = match.group(1)
        suffix = match.group(2) if match.group(2) else ""
        parsed_rules.append((line, domain, suffix))

    deleted_count = 0

    print(f"\n🧹 正在处理 {list_name}...（共 {len(parsed_rules)} 条规则）")

    for line, domain, suffix in parsed_rules:
        base = get_base_domain(domain)
        key = (base, suffix)

        if key not in keep_dict:
            keep_dict[key] = line
            cleaned.append(line)
        else:
            # 检查是否为子域（如 a.example.com 属于 example.com）
            if domain.endswith(base) and domain != base:
                deleted_count += 1
                print(f"🗑️ 匹配删除: {line}  → 保留父域: {keep_dict[key]}")
                continue
            else:
                cleaned.append(line)

    print(f"✅ {list_name} 清理完成：共删除 {deleted_count} 条\n")
    return cleaned, deleted_count

# ===============================
# 🧹 分别处理白名单与黑名单
# ===============================
cleaned_whitelist, deleted_whitelist = process_rules(whitelist, "@@||", "白名单")
cleaned_blocklist, deleted_blocklist = process_rules(blocklist, "||", "黑名单")

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
# 🧾 生成头部信息（独立显示）
# ===============================
def generate_header(list_type, url, original_count, deleted_count, current_count, diff_count):
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
#   当父域与子域（包括相同后缀）同时存在时，保留父域规则。
#   例如：||beyondthewords.co.uk^ 与 ||a.beyondthewords.co.uk^ → 保留前者。
# ==========================================================
"""
    return header

header_whitelist = generate_header(
    "白名单", whitelist_url, len(whitelist), deleted_whitelist, len(cleaned_whitelist), diff_w
)
header_blocklist = generate_header(
    "黑名单", blocklist_url, len(blocklist), deleted_blocklist, len(cleaned_blocklist), diff_b
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

write_current_count(len(cleaned_whitelist), len(cleaned_blocklist))

# ===============================
# ✅ 控制台输出摘要
# ===============================
print("✅ 构建完成！")
print(f"白名单清理后: {len(cleaned_whitelist)} 条（删除 {deleted_whitelist} 条）")
print(f"黑名单清理后: {len(cleaned_blocklist)} 条（删除 {deleted_blocklist} 条）")
print("输出文件: cleaned_whitelist.txt, cleaned_blocklist.txt")
