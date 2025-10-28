#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import dns.resolver
import sys

# ===============================
# 🌐 GitHub Blocklist 地址
# ===============================
BLOCKLIST_URL = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'
OUTPUT_FILE = 'blocklist_valid.txt'

def is_valid_domain(domain: str) -> bool:
    """
    检查域名是否可解析
    """
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def clean_rule(line: str) -> str:
    """
    从规则中提取域名，用于解析检测
    """
    domain = line.lstrip('|').lstrip('.')
    domain = domain.split('^')[0]  # 去掉尾部符号
    return domain

def main():
    print("📥 下载 blocklist...")
    try:
        resp = requests.get(BLOCKLIST_URL, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"❌ 下载失败: {e}")
        sys.exit(1)

    lines = resp.text.splitlines()
    valid_rules = []

    print("🔍 开始检测规则有效性...")
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):  # 空行或注释
            continue

        # 仅对域名规则进行解析检查
        if line.startswith('||') or line.startswith('|') or line.startswith('.'):
            domain = clean_rule(line)
            if is_valid_domain(domain):
                valid_rules.append(line)
            else:
                print(f"⚠️ 删除无效规则: {line}")
        else:
            # CSS/JS 选择器或其他规则直接保留
            valid_rules.append(line)

    # 输出有效规则
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_rules))

    print(f"✅ 有效规则已保存: {OUTPUT_FILE} (共 {len(valid_rules)} 条)")

if __name__ == '__main__':
    main()
