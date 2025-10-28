#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuardHome 批量清理脚本
---------------------------------
功能：
1️⃣ 读取 urls.txt 中的所有源
2️⃣ 下载每个源的规则文件
3️⃣ 删除 AdGuardHome 无法识别或无效规则
4️⃣ 检测域名是否可解析，清理失效规则
5️⃣ 去除子域重复，仅保留父域
6️⃣ 合并所有有效规则，生成总 blocklist
7️⃣ 保存每个源的删除日志

作者：wxglenovo
"""

import dns.resolver
import concurrent.futures
import sys
import re
import os
import requests
from urllib.parse import urlparse

INPUT_FILE = 'urls.txt'              # urls.txt 文件
OUTPUT_FILE = 'blocklist_valid_merged.txt'  # 合并后的有效规则
MAX_WORKERS = 20                     # 并行线程数

resolver = dns.resolver.Resolver()
resolver.lifetime = 5
resolver.timeout = 5

checked_domains = {}  # 缓存域名解析结果

# ----------------------------
# 工具函数
# ----------------------------
def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) < 4:
        return False
    if domain in checked_domains:
        return checked_domains[domain]
    try:
        resolver.resolve(domain, 'A')
        checked_domains[domain] = True
        return True
    except Exception:
        checked_domains[domain] = False
        return False


def clean_domain(line: str) -> str:
    domain = line.lstrip('|').lstrip('.')
    domain = domain.split('^')[0]
    domain = re.sub(r'[^a-zA-Z0-9\.\-]', '', domain)
    return domain


def get_parent_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def is_useless_rule(line: str) -> bool:
    invalid_patterns = [
        r'\$\$', r'##', r'#@#', r'#\?#',
        r'\$removeparam=', r'\$redirect=', r'\$rewrite=',
        r'\$domain=', r'\$third-party',
        r'/[a-zA-Z0-9_\-]+(\.js|\.css|\.png|\.jpg|\.gif|\.svg|\.json)',
        r'\*'
    ]
    return any(re.search(p, line) for p in invalid_patterns)


def check_rule(line: str) -> str:
    line = line.strip()
    if not line or line.startswith('#'):
        return line
    if is_useless_rule(line):
        return None
    if line.startswith(('||', '|', '.')):
        if '*' in line or '$script' in line or '/' in line:
            return line
        domain = clean_domain(line)
        if is_valid_domain(domain):
            return line
        else:
            return None
    else:
        return line


def remove_subdomain_conflicts(rules):
    domain_map = {}
    final_rules = []
    deleted = []

    for line in rules:
        line_strip = line.strip()
        if not line_strip or line_strip.startswith('#'):
            final_rules.append(line_strip)
            continue
        if line_strip.startswith(('||', '|', '.')):
            domain = clean_domain(line_strip)
            parent = get_parent_domain(domain)
            if parent in domain_map:
                deleted.append(line_strip)
                continue
            else:
                domain_map[parent] = line_strip
                final_rules.append(line_strip)
        else:
            final_rules.append(line_strip)
    return final_rules, deleted


def process_url(url: str):
    """下载源文件并清理"""
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        lines = r.text.splitlines()
        print(f"📦 下载 {url} 共 {len(lines)} 条规则")
    except Exception as e:
        print(f"❌ 下载失败 {url}: {e}")
        return [], []

    # 并行检测规则
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_rule, lines))

    valid_rules = [r for r in results if r is not None]
    deleted_invalid = [lines[i].strip() for i, r in enumerate(results) if r is None]

    final_rules, deleted_subdomain = remove_subdomain_conflicts(valid_rules)
    deleted_rules = deleted_invalid + deleted_subdomain

    # 保存单个源的日志
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url)
    log_file = f"deleted_{safe_name}.log"
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join([r for r in deleted_rules if r.strip()]))

    print(f"✅ 清理完成 {url} -> 有效规则 {len(final_rules)}，删除 {len(deleted_rules)}")
    return final_rules, log_file


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ 找不到文件: {INPUT_FILE}")
        sys.exit(1)

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    all_rules = []
    logs = []

    for url in urls:
        rules, log_file = process_url(url)
        all_rules.extend(rules)
        logs.append(log_file)

    # 合并去重
    merged_rules, _ = remove_subdomain_conflicts(all_rules)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join([r for r in merged_rules if r.strip()]))

    print(f"🎉 所有源清理合并完成 -> {OUTPUT_FILE} 共 {len(merged_rules)} 条规则")
    print("日志文件:", ', '.join(logs))


if __name__ == '__main__':
    main()
