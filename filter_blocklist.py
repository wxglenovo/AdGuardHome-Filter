#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuardHome 本地 blocklist 清理脚本
---------------------------------
功能：
1️⃣ 读取当前目录下的 urls.txt
2️⃣ 删除 AdGuardHome 无法识别或无效的规则（CSS/路径/参数类）
3️⃣ 检测域名是否可解析，清理失效规则
4️⃣ 去除子域重复，仅保留父域
5️⃣ 输出有效规则与删除日志

作者：wxglenovo
"""

import dns.resolver
import concurrent.futures
import sys
import re
import os

INPUT_FILE = 'urls.txt'              # 根目录下的原始规则文件
OUTPUT_FILE = 'blocklist_valid.txt'  # 输出有效规则
LOG_FILE = 'deleted_rules.log'       # 删除日志
MAX_WORKERS = 20                     # 并行线程数，可根据软路由性能调整

# ===============================
# 🔧 DNS resolver 全局会话
# ===============================
resolver = dns.resolver.Resolver()
resolver.lifetime = 5
resolver.timeout = 5

checked_domains = {}  # 缓存域名解析结果

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
    """提取域名"""
    domain = line.lstrip('|').lstrip('.')
    domain = domain.split('^')[0]
    domain = re.sub(r'[^a-zA-Z0-9\.\-]', '', domain)
    return domain


def get_parent_domain(domain: str) -> str:
    """提取父域（用于去除子域）"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def is_useless_rule(line: str) -> bool:
    """
    判断是否为 AdGuardHome 无效规则：
    - CSS/元素隐藏选择器规则 ($$, ##, #@#, #?#)
    - URL 参数规则 ($removeparam=, $redirect=, $rewrite=)
    - 文件路径类规则 (/xx.js, /xx.png 等)
    - 含 * 通配符的复杂表达式
    """
    invalid_patterns = [
        r'\$\$', r'##', r'#@#', r'#\?#',
        r'\$removeparam=', r'\$redirect=', r'\$rewrite=',
        r'\$domain=', r'\$third-party',
        r'/[a-zA-Z0-9_\-]+(\.js|\.css|\.png|\.jpg|\.gif|\.svg|\.json)',
        r'\*'
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
        # 其他非域名规则直接保留
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
    if not os.path.exists(INPUT_FILE):
        print(f"❌ 找不到文件: {INPUT_FILE}")
        sys.exit(1)

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    print(f"📦 读取本地规则文件 {INPUT_FILE} 共 {len(lines)} 条")
    print("🔍 并行检测规则有效性中...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_rule, lines))

    valid_rules = [r for r in results if r is not None]
    deleted_invalid = [lines[i].strip() for i, r in enumerate(results) if r is None]

    final_rules, deleted_subdomain = remove_subdomain_conflicts(valid_rules)
    deleted_rules = deleted_invalid + deleted_subdomain

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
