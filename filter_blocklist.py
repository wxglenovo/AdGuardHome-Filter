#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import dns.resolver
import concurrent.futures
import sys
import os

BLOCKLIST_URL = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'
OUTPUT_FILE = 'blocklist_valid.txt'
LOG_FILE = 'deleted_rules.log'
MAX_WORKERS = 20  # 并行线程数，可根据软路由性能调整

def is_valid_domain(domain: str) -> bool:
    """检查域名是否可解析"""
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def clean_domain(line: str) -> str:
    """从规则中提取域名用于解析"""
    domain = line.lstrip('|').lstrip('.')
    domain = domain.split('^')[0]
    return domain

def check_rule(line: str) -> str:
    """检查单条规则有效性，返回 None 表示无效"""
    line = line.strip()
    if not line or line.startswith('#'):
        return line  # 注释和空行直接保留

    # 域名规则
    if line.startswith(('||', '|', '.')):
        # 包含 * 或 $script 或 / 或正则的规则直接保留
        if '*' in line or '$script' in line or '/' in line:
            return line
        domain = clean_domain(line)
        if is_valid_domain(domain):
            return line
        else:
            print(f"⚠️ 删除无效规则: {line}")
            return None
    else:
        # CSS/JS 选择器规则或其他直接保留
        return line

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
    deleted_rules = []

    print("🔍 并行检测规则有效性...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_rule, lines))

    for original, result in zip(lines, results):
        if result:
            valid_rules.append(result)
        else:
            deleted_rules.append(original)

    # 输出有效规则
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_rules))

    # 输出被删除规则日志
    if deleted_rules:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(deleted_rules))

    print(f"✅ 有效规则已保存: {OUTPUT_FILE} (共 {len(valid_rules)} 条)")
    if deleted_rules:
        print(f"📝 被删除规则日志: {LOG_FILE} (共 {len(deleted_rules)} 条)")

if __name__ == '__main__':
    main()
