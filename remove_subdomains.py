import re
import requests
import os
from datetime import datetime

# 获取 GitHub 上的白名单和黑名单文件 URL
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

# 上次记录的规则数量文件路径
last_count_file = "last_count.txt"

def fetch_file(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # 如果请求失败，会抛出异常
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"获取文件时出错: {e}")
        exit(1)

# 获取白名单和黑名单
whitelist = fetch_file(whitelist_url)
blocklist = fetch_file(blocklist_url)

# 用于存储去重后的结果
result_whitelist = set()
result_blocklist = set()

# 用于记录处理过的域名
seen_domains_whitelist = {}
seen_domains_blocklist = {}

# 统计删除的子域数量
deleted_subdomains_whitelist = 0
deleted_subdomains_blocklist = 0

# 获取父域（即二级域名及以上）
def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

# 处理规则去重
def process_rules(rules, result_set, seen_domains, deleted_count):
    for line in rules:
        if line.startswith("@@||") or line.startswith("||"):
            domain = line[4:] if line.startswith("@@||") else line[2:]
            rule_suffix = ""
            
            # 如果有规则后缀（例如 ^$generichide），提取出来
            if "^" in domain:
                domain, rule_suffix = domain.split("^", 1)
                rule_suffix = "^" + rule_suffix  # 保留规则后缀

            base_domain = get_base_domain(domain)
            
            # 检查父域 + 子域是否同时出现，且规则后缀相同
            if (base_domain, rule_suffix) not in seen_domains:
                seen_domains[(base_domain, rule_suffix)] = domain + rule_suffix
                result_set.add(f'{line}')
            else:
                # 已存在父域且规则后缀一致，删除子域规则
                deleted_count += 1
        else:
            result_set.add(line)
    return deleted_count

# 处理白名单
deleted_subdomains_whitelist = process_rules(whitelist, result_whitelist, seen_domains_whitelist, deleted_subdomains_whitelist)

# 处理黑名单
deleted_subdomains_blocklist = process_rules(blocklist, result_blocklist, seen_domains_blocklist, deleted_subdomains_blocklist)

# 读取上次的规则数量
def read_last_count():
    if os.path.exists(last_count_file):
        with open(last_count_file, 'r') as f:
            last_count = f.read().splitlines()
            if len(last_count) >= 2:
                return int(last_count[0]), int(last_count[1])
    return 0, 0  # 如果文件不存在，默认为 0

# 写入当前规则数量
def write_current_count(whitelist_count, blocklist_count):
    with open(last_count_file, 'w') as f:
        f.write(f"{whitelist_count}\n{blocklist_count}\n")

# 获取当前规则数量（去重后的数量）
current_whitelist_count = len(result_whitelist)
current_blocklist_count = len(result_blocklist)

# 获取上次的规则数量
last_whitelist_count, last_blocklist_count = read_last_count()

# 计算规则数量变化
whitelist_diff = current_whitelist_count - last_whitelist_count
blocklist_diff = current_blocklist_count - last_blocklist_count

# 生成文件头部信息（中文）
def generate_header(file_type, original_count, deleted_count, current_count, diff_count):
    return [
        f"# {file_type} 文件生成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        f"# 原始规则数量: {original_count}",
        f"# 删除的子域名数量: {deleted_count}",
        f"# 清除子域后的规则数量: {current_count}",
        f"# 与上次对比，{('增加' if diff_count > 0 else '减少') if diff_count != 0 else '无变化'} {abs(diff_count)} 条规则",
        f"# 由 GitHub Actions 处理生成"
    ]

# 输出新的白名单规则，带上中文头部信息
try:
    with open('cleaned_whitelist.txt', 'w') as f:
        header = generate_header("白名单", len(whitelist), deleted_subdomains_whitelist, current_whitelist_count, whitelist_diff)
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(sorted(result_whitelist)) + '\n')

    with open('cleaned_blocklist.txt', 'w') as f:
        header = generate_header("黑名单", len(blocklist), deleted_subdomains_blocklist, current_blocklist_count, blocklist_diff)
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(sorted(result_blocklist)) + '\n')

    # 保存当前规则数量
    write_current_count(current_whitelist_count, current_blocklist_count)

except Exception as e:
    print(f"写入文件时出错: {e}")
    exit(1)

# 输出删除的子域数量到控制台（可选）
print(f"删除的白名单子域名数量: {deleted_subdomains_whitelist}")
print(f"删除的黑名单子域名数量: {deleted_subdomains_blocklist}")
