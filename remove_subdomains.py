import re
import requests
import os
from datetime import datetime

# GitHub 上的白名单和黑名单
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

last_count_file = "last_count.txt"

def fetch_file(url):
    try:
        r = requests.get(url)
        r.raise_for_status()
        return r.text.splitlines()
    except requests.RequestException as e:
        print(f"获取文件失败: {e}")
        exit(1)

# 读取规则
whitelist = fetch_file(whitelist_url)
blocklist = fetch_file(blocklist_url)

def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def process_rules(rules):
    seen = {}
    cleaned = []
    deleted_count = 0

    for line in rules:
        line = line.strip()
        if not line or line.startswith('#'):
            cleaned.append(line)
            continue

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
                continue
        else:
            cleaned.append(line)

    return cleaned, deleted_count

# 处理白名单
cleaned_whitelist, deleted_whitelist = process_rules(whitelist)

# 处理黑名单
cleaned_blocklist, deleted_blocklist = process_rules(blocklist)

# 读取上次数量
def read_last_count():
    if os.path.exists(last_count_file):
        with open(last_count_file, 'r') as f:
            lines = f.read().splitlines()
            if len(lines) >= 2:
                return int(lines[0]), int(lines[1])
    return 0, 0

# 写入当前数量
def write_current_count(w_count, b_count):
    with open(last_count_file, 'w') as f:
        f.write(f"{w_count}\n{b_count}\n")

# 当前数量
current_w = len(cleaned_whitelist)
current_b = len(cleaned_blocklist)

# 上次数量
last_w, last_b = read_last_count()
diff_w = current_w - last_w
diff_b = current_b - last_b

def generate_header(file_type, original_count, deleted_count, current_count, diff):
    return [
        f"# {file_type} 文件生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 原始规则数量: {original_count}",
        f"# 删除的子域名数量: {deleted_count}",
        f"# 清除子域后的规则数量: {current_count}",
        f"# 与上次对比: {('增加' if diff>0 else '减少') if diff!=0 else '无变化'} {abs(diff)} 条规则",
        f"# 由 GitHub Actions 自动生成"
    ]

# 输出白名单
with open("cleaned_whitelist.txt", "w", encoding="utf-8") as f:
    header = generate_header("白名单", len(whitelist), deleted_whitelist, current_w, diff_w)
    f.write('\n'.join(header) + '\n\n')
    f.write('\n'.join(sorted(cleaned_whitelist)) + '\n')

# 输出黑名单
with open("cleaned_blocklist.txt", "w", encoding="utf-8") as f:
    header = generate_header("黑名单", len(blocklist), deleted_blocklist, current_b, diff_b)
    f.write('\n'.join(header) + '\n\n')
    f.write('\n'.join(sorted(cleaned_blocklist)) + '\n')

write_current_count(current_w, current_b)

print(f"白名单删除子域数量: {deleted_whitelist}")
print(f"黑名单删除子域数量: {deleted_blocklist}")
