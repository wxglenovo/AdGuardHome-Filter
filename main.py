#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import dns.resolver
import concurrent.futures
import os
import sys

URLS_FILE = "urls.txt"
OUTPUT_DIR = "dist"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "blocklist_valid.txt")
LOG_FILE = os.path.join(OUTPUT_DIR, "deleted_rules.log")
MAX_WORKERS = 30  # 并行线程数，可按性能调整

def fetch_rules(url):
    """下载单个规则文件"""
    try:
        print(f"⬇️ 正在下载: {url}")
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        print(f"❌ 下载失败: {url} - {e}")
        return []

def is_valid_domain(domain: str) -> bool:
    """检查域名是否可解析"""
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def clean_domain(line: str) -> str:
    """从规则中提取域名"""
    domain = line.lstrip('|').lstrip('.')
    domain = domain.split('^')[0]
    return domain.strip()

def check_rule(line: str) -> str | None:
    """检查单条规则有效性"""
    line = line.strip()
    if not line or line.startswith('#'):
        return line  # 保留注释和空行
    if line.startswith(('||', '|', '.')):
        if '*' in line or '$' in line or '/' in line:
            return line
        domain = clean_domain(line)
        if is_valid_domain(domain):
            return line
        else:
            print(f"⚠️ 删除无效规则: {line}")
            return None
    return line

def main():
    print("📘 读取 urls.txt ...")
    if not os.path.exists(URLS_FILE):
        print("❌ 未找到 urls.txt")
        sys.exit(1)

    with open(URLS_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # 下载与合并规则
    print(f"🌐 共 {len(urls)} 个规则源，开始下载...")
    all_rules = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_rules, urls)
        for lines in results:
            all_rules.extend(lines)

    print(f"🧹 合并前规则总数: {len(all_rules)}")
    all_rules = list(dict.fromkeys(all_rules))  # 去重
    print(f"✅ 去重后规则总数: {len(all_rules)}")

    # 检查域名有效性
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    valid_rules = []
    deleted_rules = []

    print("🔍 开始检测规则有效性...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_rule, all_rules))

    for original, result in zip(all_rules, results):
        if result:
            valid_rules.append(result)
        else:
            deleted_rules.append(original)

    # 输出结果
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write('\n'.join(valid_rules))
    print(f"✅ 有效规则已保存至: {OUTPUT_FILE}")

    if deleted_rules:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write('\n'.join(deleted_rules))
        print(f"📝 被删除规则日志已保存: {LOG_FILE} (共 {len(deleted_rules)} 条)")

if __name__ == "__main__":
    main()
