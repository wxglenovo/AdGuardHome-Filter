#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
from datetime import datetime
from urllib.parse import urlparse

# ==========================================================
# 📌 规则来源
# ==========================================================
whitelist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/whitelist.txt'
blocklist_url = 'https://raw.githubusercontent.com/wxglenovo/AdGuardHome-Filter/refs/heads/main/dist/blocklist.txt'

# ==========================================================
# 📌 下载规则文件
# ==========================================================
def download_rules(url):
    resp = requests.get(url, timeout=60)
    resp.encoding = 'utf-8'
    lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
    return lines

# ==========================================================
# 📌 提取域名与规则后缀
# ==========================================================
def extract_domain_and_suffix(rule):
    match = re.match(r'(@@)?\|\|([^/^$]+)(.*)', rule)
    if match:
        prefix = match.group(1) or ''
        domain = match.group(2).strip('.')
        suffix = match.group(3)
        return prefix, domain, suffix
    return '', '', ''

# ==========================================================
# 📌 判断是否为子域
# ==========================================================
def is_subdomain(child, parent):
    return child.endswith('.' + parent)

# ==========================================================
# 📌 清理逻辑
# ==========================================================
def clean_rules(rules):
    parsed = []
    for rule in rules:
        prefix, domain, suffix = extract_domain_and_suffix(rule)
        if domain:
            parsed.append((prefix, domain, suffix, rule))

    cleaned = []
    domains = sorted(parsed, key=lambda x: x[1].count('.'))  # 按级数从低到高

    skip = set()
    for i, (prefix_i, domain_i, suffix_i, rule_i) in enumerate(domains):
        if rule_i in skip:
            continue
        for j, (prefix_j, domain_j, suffix_j, rule_j) in enumerate(domains):
            if i != j and rule_j not in skip:
                if is_subdomain(domain_j, domain_i) and suffix_i == suffix_j and prefix_i == prefix_j:
                    skip.add(rule_j)
    for prefix, domain, suffix, rule in domains:
        if rule not in skip:
            cleaned.append(rule)

    return cleaned, len(skip)

# ==========================================================
# 📌 输出头部信息
# ==========================================================
def build_header(stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S CST")
    header = f"""###########################################################
# 📅 AdGuardHome 综合规则自动构建信息
# ⏰ 更新时间: {now}
# 🌐 规则来源:
#   白名单: {whitelist_url}
#   黑名单: {blocklist_url}
# --------------------------------------------------------
# 📊 白名单统计:
#   ▸ 原始规则数量: {stats['white_total']}
#   ▸ 删除子域数量: {stats['white_removed']}
#   ▸ 清理后规则数量: {stats['white_final']}
# --------------------------------------------------------
# 📊 黑名单统计:
#   ▸ 原始规则数量: {stats['black_total']}
#   ▸ 删除子域数量: {stats['black_removed']}
#   ▸ 清理后规则数量: {stats['black_final']}
# --------------------------------------------------------
# 🧩 规则处理逻辑说明:
#   1️⃣ 当父域与子域（包括规则后缀）同时存在时，保留父域规则，删除子域规则。
#   2️⃣ 多级子域（如三级、四级）则保留级数更低的域名（父域）。
#   3️⃣ 若无匹配子域，仅保留主规则（如 @@||baidu.com^*&cb=BaiduSuggestion）。
# ==========================================================
! =====================
! 🔰 AdGuardHome 综合规则开始
! =====================
"""
    return header

# ==========================================================
# 📌 主执行逻辑
# ==========================================================
def main():
    print("📥 开始下载规则文件...")
    whitelist = download_rules(whitelist_url)
    blocklist = download_rules(blocklist_url)

    print("🧹 开始清理白名单规则...")
    cleaned_white, removed_white = clean_rules(whitelist)

    print("🧹 开始清理黑名单规则...")
    cleaned_black, removed_black = clean_rules(blocklist)

    stats = {
        "white_total": len(whitelist),
        "white_removed": removed_white,
        "white_final": len(cleaned_white),
        "black_total": len(blocklist),
        "black_removed": removed_black,
        "black_final": len(cleaned_black),
    }

    header = build_header(stats)
    output = header + "\n".join(cleaned_white + cleaned_black)

    with open("AdGuardHome_Filter.txt", "w", encoding="utf-8") as f:
        f.write(output)

    print("✅ 构建完成，输出文件：AdGuardHome_Filter.txt")

# ==========================================================
if __name__ == "__main__":
    main()
