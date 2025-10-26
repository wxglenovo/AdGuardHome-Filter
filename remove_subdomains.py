import re
import requests
from datetime import datetime

# 获取 GitHub 上的白名单和黑名单文件 URL
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

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

# 用于存储结果
result_whitelist = set()
result_blocklist = set()

# 用于记录处理过的域名
seen_domains_whitelist = {}
seen_domains_blocklist = {}

# 统计删除的子域数量
deleted_subdomains_whitelist = 0
deleted_subdomains_blocklist = 0

# 处理白名单
for line in whitelist:
    if line.startswith("@@||"):
        # 获取域名部分
        domain = line[4:]
        parts = domain.split('.')
        
        # 保留较高级别的域名
        if len(parts) >= 2:
            domain_key = '.'.join(parts[-2:])
        else:
            domain_key = domain
            
        # 如果该父域名没有被处理过，加入结果
        if domain_key not in seen_domains_whitelist:
            seen_domains_whitelist[domain_key] = domain
            result_whitelist.add(f'@@||{domain_key}')
        else:
            deleted_subdomains_whitelist += 1
    else:
        result_whitelist.add(line)

# 处理黑名单
for line in blocklist:
    if line.startswith("||"):
        # 获取域名部分
        domain = line[2:]
        parts = domain.split('.')
        
        # 保留较高级别的域名
        if len(parts) >= 2:
            domain_key = '.'.join(parts[-2:])
        else:
            domain_key = domain
            
        # 如果该父域名没有被处理过，加入结果
        if domain_key not in seen_domains_blocklist:
            seen_domains_blocklist[domain_key] = domain
            result_blocklist.add(f'||{domain_key}')
        else:
            deleted_subdomains_blocklist += 1
    else:
        result_blocklist.add(line)

# 生成文件头部信息（中文）
def generate_header(file_type, original_count, deleted_count):
    return [
        f"# {file_type} 文件生成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        f"# 原始规则数量: {original_count}",
        f"# 删除的子域名数量: {deleted_count}",
        f"# 由 GitHub Actions 处理生成"
    ]

# 输出新的白名单规则，带上中文头部信息
try:
    with open('cleaned_whitelist.txt', 'w') as f:
        header = generate_header("白名单", len(whitelist), deleted_subdomains_whitelist)
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(sorted(result_whitelist)) + '\n')

    with open('cleaned_blocklist.txt', 'w') as f:
        header = generate_header("黑名单", len(blocklist), deleted_subdomains_blocklist)
        f.write('\n'.join(header) + '\n\n')
        f.write('\n'.join(sorted(result_blocklist)) + '\n')

except Exception as e:
    print(f"写入文件时出错: {e}")
    exit(1)

# 输出删除的子域数量到控制台（可选）
print(f"删除的白名单子域名数量: {deleted_subdomains_whitelist}")
print(f"删除的黑名单子域名数量: {deleted_subdomains_blocklist}")
