#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuardHome Blocklist 清理脚本
---------------------------------
功能：
1️⃣ 下载 blocklist.txt
2️⃣ 删除 AdGuardHome 无法识别或无效的规则（路径类、CSS 选择器等）
3️⃣ 检测域名可解析性，删除失效域名
4️⃣ 保留父域，去掉子域重复
5️⃣ 输出有效规则与删除日志

作者：wxglenovo
"""

import requests
import dns.resolver
import concurrent.futures
import sys
import re

BLOCKLIST_URL = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'
OUTPUT_FILE = 'blocklist_valid.txt'
LOG_FILE = 'deleted_rules.log'
MAX_WORKERS = 20  # 并行线程数，可根据软路由性能调整

# ===============================
# 🔧 DNS resolver 全局会话
# ===============================
resolver = dns.resolver.Resolver()
resolver.lifetime = 5
resolver.timeout = 5

checked_domains = {}  # 域名解析缓存

# ===============================
# 🧩 工具函数
# ===============================
def is_valid_domain(domain: str) -> bool:
    """检查域名是否可解析"""
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
    """从规则中提取域名"""
    domain = line.lstrip('|').lstrip('.')
    domain = domain.split('^')[0]
    domain = re.sub(r'[^a-zA-Z0-9\.\-]', '', domain)
    return domain


def get_parent_domain(domain: str) -> str:
    """提取二级或以上父域名"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def is_useless_rule(line: str) -> bool:
    """
    判断是否为 AdGuardHome 无效规则：
    - CSS / JS 选择器（$$、##）
    - 元素隐藏规则 (#@#、#?#)
    - URL 参数过滤 ($removeparam=xxx)
    - Scriptlet / redirect ($redirect=、$rewrite=)
    - 非域名类路径 (/、*.js、*.png 等)
    """
    invalid_patterns = [
        r'\$\$', r'##', r'#@#', r'#\?#',  # CSS / 元素隐藏规则
        r'\$removeparam=', r'\$redirect=', r'\$rewrite=',
        r'\$domain=', r'\$third-party',  # 特定过滤参数
        r'/[a-zA-Z0-9_\-]+(\.js|\.css|\.png|\.jpg|\.gif|\.svg|\.json)',  # 文件路径类
        r'\*'  # 通配符（多数 AdGuardHome 不支持）
    ]
    return any(re.search(p, line) for p in invalid_patterns)


# ===============================
# 🔍 检查规则有效性
# ===============================
def check_rule(line: str) -> str:
    """返回 None 表示无效"""
    line = line.strip()
    if not line or line.startswith('#'):
        return line  # 注释保留

    # 删除明显无效的 AdGuardHome 不支持规则
    if is_useless_rule(line):
        print(f"🚫 删除 AdGuardHome 无效规则: {line}")
        return None

    # 域名规则检测
    if line.startswith(('||', '|', '.')):
        if '*' in line or '$script' in line or '/' in line:
            return line  # 特殊或路径规则直接保留
        domain = clean_domain(line)
        if is_valid_domain(domain):
            return line
        else:
            print(f"⚠️ 删除不可解析域名规则: {line}")
            return None
    else:
        # 其他规则直接保留
        return line


# ===============================
# 🧹 去除子域名冲突
# ===============================
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


# ===============================
# 🧾 主程序
# ===============================
def main():
    print("📥 正在下载 blocklist...")
    try:
        resp = requests.get(BLOCKLIST_URL, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"❌ 下载失败: {e}")
        sys.exit(1)

    lines = resp.text.splitlines()
    print(f"📦 规则总数: {len(lines)} 条")
    print("🔍 并行检测规则有效性中...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_rule, lines))

    # 筛选结果
    valid_rules = [r for r in results if r is not None]
    deleted_invalid = [lines[i] for i, r in enumerate(results) if r is None]

    # 去除子域名冲突
    final_rules, deleted_subdomain = remove_subdomain_conflicts(valid_rules)
    deleted_rules = deleted_invalid + deleted_subdomain

    # 输出文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join([r for r in final_rules if r.strip()]))

    if deleted_rules:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join([r for r in deleted_rules if r.strip()]))

    print(f"✅ 有效规则已保存: {OUTPUT_FILE} ({len(final_rules)} 条)")
    if deleted_rules:
        print(f"🗑️ 删除无效规则日志: {LOG_FILE} ({len(deleted_rules)} 条)")
    print("🎉 清理完成！")


# ===============================
# 🚀 入口
# ===============================
if __name__ == '__main__':
    main()
