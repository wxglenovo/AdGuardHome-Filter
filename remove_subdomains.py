import re
import requests

# 从 GitHub 获取白名单文件
url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
response = requests.get(url)
whitelist = response.text.splitlines()

# 用于存储结果
result = set()

# 用于记录处理过的域名
seen_domains = {}

# 处理每行规则
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
        if domain_key not in seen_domains:
            seen_domains[domain_key] = domain
            result.add(f'@@||{domain_key}')
    else:
        result.add(line)

# 输出新的白名单规则
with open('cleaned_whitelist.txt', 'w') as f:
    f.write('\n'.join(sorted(result)) + '\n')
