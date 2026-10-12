#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UI components for CliShell.
Sliver C2 风格的终端 UI：随机 Banner、分类帮助、彩色消息前缀。
"""

import random
import shutil
from colorama import init, Fore, Style

init(autoreset=True)


# ═══════════════════════════════════════════════════════════════
#  Sliver-style ASCII Logos
# ═══════════════════════════════════════════════════════════════

_ascii_logos = [
    (Fore.RED, r'''
  _     ____  _     ___ _   _ _   _ ____  _
 | |   |  _ \| |   |_ _| \ | | | | / ___|| |
 | |   | |_) | |    | ||  \| | | | \___ \| |
 | |___|  __/| |___ | || |\  | |_| |___) | |___
 |_____|_|   |_____|___|_| \_|\___/|____/|_____|''' + '\n'),
    (Fore.GREEN, r'''
 _         _   _ _____ ___  ____   _     ___ _   _ _   _ ____  _
| |       | | | | ____|_ _|/ ___| | |   |_ _| \ | | | | / ___|| |
| |       | | | |  _|  | | \___ \ | |    | ||  \| | | | \___ \| |
| |____   | |_| | |___ | |  ___) || |___ | || |\  | |_| |___) | |___
|______|   \___/|_____|___| |____/ |_____|___|_| \_|\___/|____/|_____|''' + '\n'),
    (Fore.LIGHTYELLOW_EX, r"""
.------..------..------..------..------..------..------..------.
|L.--. ||D.--. ||A.--. ||P.--. ||S.--. ||H.--. ||E.--. ||L.--. |
| :/\  || :/\  || (\/) || :(): || :/\  || :/\  || (\/) || :/\  |
| :\/  || (__) || :\/  || ()() || :\/  || (__) || :\/  || (__) |
| '--'L|| '--'D|| '--'A|| '--'P|| '--'S|| '--'H|| '--'E|| '--'L|
`------'`------'`------'`------'`------'`------'`------'`------'""" + '\n'),
]

_taglines = [
    "first strike", "vigilance", "haste", "indestructible",
    "hexproof", "deathtouch", "epic", "infect", "undying",
    "prowess", "annihilator", "exploit",
]


# ═══════════════════════════════════════════════════════════════
#  Help Items — 分分类命令表
# ═══════════════════════════════════════════════════════════════

help_items = [
    ("Computer Management", [
        ("add_computer <computer> [password] [nospns]", "创建机器账户 (需要 LDAPS)"),
        ("delete_computer <computer>", "删除机器账户"),
        ("move_computer <computer> <ou>", "移动机器到指定 OU"),
        ("get_computer <computer>", "查看机器完整详情 (SPN/组/Owner/登录)"),
    ]),
    ("User Management", [
        ("add_user <user> [ou]", "创建用户 (需要 LDAPS)"),
        ("delete_user <user>", "删除用户"),
        ("get_user <user>", "查看用户完整详情 (含组/登录/密码)"),
        ("unlock_user <user>", "解锁用户"),
    ]),
    ("Group Management", [
        ("add_group <group>", "创建组"),
        ("delete_group <group>", "删除组"),
        ("get_group <group>", "查看组详情"),
        ("list_groups", "枚举所有组"),
        ("group_members <group>", "查看组成员"),
        ("group_owner <group>", "查看组 Owner"),
        ("add_group_member <group> <user>", "添加组成员"),
        ("remove_group_member <group> <user>", "删除组成员"),
        ("nested_groups <group>", "查看嵌套组"),
    ]),
    ("OU Management", [
        ("list_ous", "枚举所有 OU"),
        ("get_ou <ou>", "查看 OU 详情"),
        ("create_ou <ou>", "创建 OU"),
        ("delete_ou <ou>", "删除 OU"),
        ("move_object <dn> <ou>", "移动对象到 OU"),
        ("ou_acl <ou>", "查看 OU 的 ACL"),
    ]),
    ("Domain / Trust", [
        ("domain_trusts", "域信任关系"),
        ("domain_sites", "AD Sites"),
        ("domain_subnets", "AD Subnets"),
        ("forest_info", "Forest 信息"),
        ("forest_domains", "Forest 下的所有域"),
        ("get_rodc [rodc_name]", "RODC 信息 (列表 / 密码策略 / 缓存密码 / krbtgt / 管理员)"),
    ]),
    ("DNS Info", [
        ("dns_zones", "DNS 区域列表 (域/林/旧版)"),
        ("dns_records <zone>", "DNS 记录 (MS-DNSP 二进制解析)"),
        ("dns_hosts", "主机 IP (computer 对象保底)"),
        ("dns_servers", "DNS 服务器"),
    ]),
    ("Exchange", [
        ("get_exchange", "Exchange 综合信息 (IP/版本/CVE/URL)"),
    ]),
    ("ADCS / WSUS", [
        ("get_adcs", "ADCS 信息 (企业CA / 模板 / ESC1漏洞 / NTAuth)"),
        ("get_wsus", "WSUS 服务器发现 (GPO扩展 + SPN)"),
    ]),
    ("Delegation / BloodHound", [
        ("find_delegation [object]", "全域委派审计 / 单对象委派详情"),
        ("set_rbcd <target> <grantee>", "设置 RBCD (可 S4U)"),
        ("remove_rbcd <target>", "移除 RBCD"),
        ("find_shadowcredentials", "Shadow Credentials 对象"),
        ("add_shadowcredential <target> <user>", "创建 Shadow Credential"),
        ("remove_shadowcredential <target> <user>", "删除 Shadow Credential"),
    ]),
    ("ACL / 权限", [
        ("object_acl <object>", "查看对象 ACL (入站+出站)"),
        ("find_interesting_acl", "综合敏感 ACL 审计 (BloodHound-style)"),
        ("find_generic_all", "GenericAll 权限发现"),
        ("find_generic_write", "GenericWrite 权限发现"),
        ("find_write_owner", "WriteOwner 权限发现"),
        ("find_write_dacl", "WriteDacl 权限发现"),
        ("find_all_extended_rights", "AllExtendedRights 权限发现"),
        ("find_force_change_password", "ForceChangePassword 权限发现"),
        ("find_add_member", "AddMember 权限发现 (向组添加成员)"),
        ("find_add_self", "AddSelf 权限发现 (将自身加入组)"),
        ("find_read_laps", "ReadLAPSPassword 权限发现"),
        ("find_read_gmsa", "ReadGMSAPassword 权限发现"),
        ("find_gp_link", "GpLink 权限发现 (链接 GPO)"),
        ("find_write_spn", "WriteSPN 权限发现 (Targeted Kerberoast)"),
        ("find_write_account_restrictions", "WriteAccountRestrictions 权限发现"),
        ("find_write_property", "WriteProperty 权限发现 (写特定属性)"),
        ("find_create_child", "CreateChild 权限发现 (创建子对象)"),
        ("find_sid_history", "SIDHistory 对象发现"),
        ("find_owns", "非默认 Owner 对象发现"),
        ("grant_control <target> <grantee>", "授予 GenericAll (完全控制)"),
        ("grant_generic_write <target> <grantee>", "授予 GenericWrite"),
        ("grant_write_dacl <target> <grantee>", "授予 WriteDacl"),
        ("grant_write_owner <target> <grantee>", "授予 WriteOwner"),
        ("grant_all_extended_rights <target> <grantee>", "授予 AllExtendedRights"),
        ("grant_force_change_password <target> <grantee>", "授予 ForceChangePassword"),
        ("grant_add_member <group> <grantee>", "授予 AddMember (向组添加成员)"),
        ("grant_add_self <group> <grantee>", "授予 AddSelf (将自身加入组)"),
        ("grant_write_spn <target> <grantee>", "授予 WriteSPN (Targeted Kerberoast)"),
        ("grant_write_account_restrictions <target> <grantee>", "授予 WriteAccountRestrictions"),
        ("grant_read_laps <computer> <grantee>", "授予 ReadLAPSPassword"),
        ("grant_read_gmsa <target> <grantee>", "授予 ReadGMSAPassword"),
        ("set_dcsync <user>", "授予 DCSync 权限"),
        ("get_dcsync", "查看具有 DCSync 权限的对象"),
        ("remove_dcsync <user>", "撤销 DCSync 权限"),
        ("revoke_ace <target> <grantee>", "移除 grantee 对 target 的所有 ACE"),
        ("write_gpo_dacl <user> <gpoSID>", "写入 GPO DACL"),
    ]),
    ("Session / 登录", [
        ("computer_sessions <target>", "查看目标的 SMB 会话 (谁连到它的共享) [RPC]"),
        ("user_sessions <target>", "查看目标上本地登录的用户 [RPC]"),
        ("find_sessions <username>", "全域搜索用户在哪台机器登录 [RPC]"),
        ("active_users", "近期活跃用户 (LDAP lastLogonTimestamp)"),
    ]),
    ("Privilege / 高权限账户", [
        ("find_privileged_users", "综合审计 (特权组 + AdminCount + Exchange)"),
    ]),
    ("Trust / Forest", [
        ("trusts", "信任关系"),
        ("trust_map", "信任拓扑"),
        ("external_trusts", "外部信任"),
        ("forest_trusts", "Forest 信任"),
    ]),
    ("GPO", [
        ("gpo_list", "GPO 列表"),
        ("gpo_info <gpo>", "GPO 详细信息"),
        ("gpo_links", "GPO 链接关系"),
        ("gpo_permissions", "GPO 权限"),
        ("gpo_security_filtering", "GPO 安全筛选"),
    ]),
    ("Search", [
        ("search <query> [attrs]", "通用搜索 (用户/组/机器)"),
        ("search_user <keyword>", "搜索用户"),
        ("search_group <keyword>", "搜索组"),
        ("search_computer <keyword>", "搜索机器"),
        ("search_ou <keyword>", "搜索 OU"),
        ("search_spn <keyword>", "搜索 SPN"),
    ]),
    ("Security Assessment", [
        ("find_kerberoastable", "Kerberoastable 用户 (有 SPN 的启用账户)"),
        ("find_preauth_disabled", "AS-REP Roastable 用户 (不需预认证) + CVE-2022-33679 检测"),
        ("find_gpp_passwords", "GPP 密码解密 (SYSVOL Groups.xml 等)"),
        ("find_sysvol_files [keyword]", "SYSVOL 敏感文件 (脚本/配置/凭据)"),
        ("find_sysvol_secrets", "SYSVOL 文件敏感信息扫描 (密码/密钥)"),
    ]),
    ("Connection", [
        ("get_basic_info", "域基本信息 (用户/机器/会话状态)"),
        ("start_tls", "升级 LDAP → LDAPS"),
        ("dump", "Dump 域信息到文件"),
        ("get_laps_password <computer>", "获取 LAPS 密码"),
        ("exit", "退出"),
    ]),
]


# ═══════════════════════════════════════════════════════════════
#  Banner / Help / Message Helpers
# ═══════════════════════════════════════════════════════════════

def print_banner():
    """启动横幅：版本 + tagline"""
    tagline = random.choice(_taglines)
    print()
    print(Fore.WHITE + Style.BRIGHT + "  CliShell" + Fore.LIGHTBLACK_EX + " v1.0")
    print(Fore.WHITE + Style.BRIGHT + "  ────────")
    print(Fore.WHITE + Style.BRIGHT + "  All hackers gain " + Fore.YELLOW + tagline)
    print()


def print_help():
    """impacket 风格帮助 — 统一大表格"""
    all_cmds = [cmd for _, items in help_items for cmd, _ in items]
    max_cmd_len = max(len(cmd) for cmd in all_cmds)

    print()
    header = 'Command'.ljust(max_cmd_len) + '  Description'
    sep    = '-' * max_cmd_len + '  ' + '-' * 20
    print(Fore.LIGHTBLACK_EX + header)
    print(Fore.LIGHTBLACK_EX + sep)

    for section, items in help_items:
        for cmd, desc in items:
            print(Fore.GREEN + cmd.ljust(max_cmd_len) + Style.RESET_ALL + '  ' + Fore.WHITE + desc)

    print()


# ── Sliver-style 彩色消息前缀 ────────────────────────────────

def print_info(msg):
    """蓝色 [*] — 一般信息"""
    print(Fore.BLUE + Style.BRIGHT + "[*] " + Style.RESET_ALL + Fore.WHITE + str(msg))


def print_success(msg):
    """绿色 [+] — 操作成功"""
    print(Fore.GREEN + Style.BRIGHT + "[+] " + Style.RESET_ALL + Fore.GREEN + str(msg))


def print_error(msg):
    """红色 [-] — 错误"""
    print(Fore.RED + Style.BRIGHT + "[-] " + Style.RESET_ALL + Fore.RED + str(msg))


def print_warn(msg):
    """黄色 [!] — 警告"""
    print(Fore.YELLOW + Style.BRIGHT + "[!] " + Style.RESET_ALL + Fore.YELLOW + str(msg))


def print_found(msg):
    """灰色 [·] — 发现/细节"""
    print(Fore.LIGHTBLACK_EX + "[·] " + Style.RESET_ALL + Fore.WHITE + str(msg))


def print_header(title):
    """青色标题栏"""
    width = shutil.get_terminal_size((80, 20)).columns
    print()
    print(Fore.CYAN + Style.BRIGHT + "═" * width)
    print(Fore.CYAN + Style.BRIGHT + f"  {title}")
    print(Fore.CYAN + Style.BRIGHT + "═" * width)
    print(Style.RESET_ALL)
