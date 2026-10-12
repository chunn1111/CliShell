#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Privilege Mixin — 高权限账户发现命令 (1 个)
综合审计：高权限组成员 + AdminCount=1 + Exchange 特权组/RBAC 危险角色
"""

import re
import ldap3
from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import (
    LDAP_MATCHING_RULE_IN_CHAIN,
    paged_search,
)


# 待审计的高权限组列表
_PRIV_GROUPS = [
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Backup Operators',
    'Account Operators',
    'Server Operators',
    'Print Operators',
    # 远程访问组
    'Remote Desktop Users',
    'Remote Management Users',
    'Network Configuration Operators',
    # 基础设施滥用 (DnsAdmins 可在 DC 加载 DLL, Hyper-V 可读 DC 虚拟机磁盘)
    'DnsAdmins',
    'DHCP Administrators',
    'Hyper-V Administrators',
    'Storage Replica Administrators',
    # 证书 / 密钥信任
    'Cert Publishers',
    'Key Admins',
    'Enterprise Key Admins',
    # 域控 / GPO
    'Domain Controllers',
    'Read-only Domain Controllers',
    'Group Policy Creator Owners',
    # Exchange 特权组
    'Exchange Windows Permissions',
    'Organization Management',
    'Hygiene Management',
]

# Exchange RBAC 危险角色 (存于 Configuration NC 的 msExchRoleAssignment,
# 不是域组, 需要单独审计):
#   ApplicationImpersonation — EWS 冒充任何用户收发/阅读邮件;
#     默认无任何持有者, 出现即高度可疑 (尤其分配给 Hygiene Management 等非管理组)
#   Mailbox Import Export    — New-MailboxExportRequest 导出任意邮箱 .pst;
#     默认仅 Organization Management (Delegating)
_EXCH_DANGEROUS_ROLES = ['ApplicationImpersonation', 'Mailbox Import Export']


class PrivilegeMixin:
    """Privilege / 高权限账户命令集"""

    # ── find_privileged_users ───────────────────────────────────
    def do_find_privileged_users(self, line):
        """find_privileged_users — 综合高权限账户审计 (特权组 + AdminCount + Exchange)"""
        print_info("Auditing privileged users...")

        # user_dn → {sam, groups:[], admin_count:bool, disabled:bool}
        users = {}

        # ── 1. 逐组递归查询成员 ───────────────────────────────
        for group_name in _PRIV_GROUPS:
            self._collect_group_members(group_name, users)

        # ── 1.5 Exchange RBAC 危险角色受让人 ──────────────────
        exch_assignments = self._collect_exchange_role_members(users)
        for role, assignee_cn in exch_assignments:
            if role == 'ApplicationImpersonation':
                print_warn("ApplicationImpersonation → %s: "
                           "成员可冒充任何用户收发/阅读邮件 (EWS)" % assignee_cn)
            else:
                print_warn("Mailbox Import Export → %s: "
                           "可导出任意邮箱 .pst (New-MailboxExportRequest)" % assignee_cn)

        # ── 2. AdminCount=1 账户 ────────────────────────────────
        admin_count_entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(adminCount=1))',
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl'],
        )
        for entry in admin_count_entries:
            dn = entry.entry_dn
            sam = entry['sAMAccountName'].value
            uac = entry['userAccountControl'].value or 0
            if dn not in users:
                users[dn] = {
                    'sam': sam,
                    'groups': [],
                    'admin_count': True,
                    'disabled': bool(uac & 0x0002),
                }
            else:
                users[dn]['admin_count'] = True

        if not users:
            print_warn("No privileged users found")
            return

        # ── 3. 横排表格输出 ────────────────────────────────────
        sorted_users = sorted(users.values(), key=lambda u: (-len(u['groups']), u['sam']))

        header = ['Username', 'Disabled', 'adminCnt', 'Groups']
        rows = []
        for u in sorted_users:
            groups_str = ', '.join(u['groups']) if u['groups'] else '-'
            if u['admin_count'] and 'AdminCount=1' not in groups_str:
                groups_str += ' [AdminCount=1]' if groups_str != '-' else '[AdminCount=1]'
            rows.append([
                u['sam'],
                'Yes' if u['disabled'] else 'No',
                '1' if u['admin_count'] else '0',
                groups_str,
            ])

        col_lens = [max(len(header[i]), max(len(r[i]) for r in rows)) for i in range(len(header))]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        for r in rows:
            print(fmt.format(*r))

    # ── 内部辅助 ──────────────────────────────────────────────
    @staticmethod
    def _add_user(users, entry, label):
        """把一个 entry 合并进 users dict, groups 列追加 label"""
        dn = entry.entry_dn
        sam = entry['sAMAccountName'].value
        if not sam:
            return
        uac = entry['userAccountControl'].value or 0
        if dn not in users:
            users[dn] = {
                'sam': sam,
                'groups': [label],
                'admin_count': False,
                'disabled': bool(uac & 0x0002),
            }
        elif label not in users[dn]['groups']:
            users[dn]['groups'].append(label)

    def _collect_group_members(self, group_name, users):
        """递归查找指定组的所有成员，结果合并到 users dict"""
        # 找到组的 DN
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=group)(sAMAccountName=%s))' % escape_filter_chars(group_name),
            attributes=['distinguishedName'],
        )
        if not self.client.entries:
            return  # 组不存在（如 Exchange 未安装），跳过

        group_dn = self.client.entries[0].entry_dn

        # LDAP_MATCHING_RULE_IN_CHAIN 递归查所有成员
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(memberof:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(group_dn)),
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl'],
        )
        for entry in entries:
            self._add_user(users, entry, group_name)

    def _collect_exchange_role_members(self, users):
        """
        查询 Exchange RBAC 危险角色 (ApplicationImpersonation / Mailbox Import Export)
        的角色分配 (Configuration NC 的 msExchRoleAssignment 对象),
        受让人为组时递归展开成员, 合并到 users dict。
        返回 [(role, assignee_cn)] 供调用方打印告警; Exchange 未安装返回空列表。
        """
        assignments = []

        # Configuration NC (从 RootDSE 取, 子域环境也能定位)
        config_nc = None
        try:
            self.client.search('', '(objectClass=*)', search_scope=ldap3.BASE,
                               attributes=['configurationNamingContext'])
            if self.client.entries:
                config_nc = str(self.client.entries[0]['configurationNamingContext'].value)
        except Exception:
            pass
        if not config_nc:
            config_nc = 'CN=Configuration,%s' % self.domain_dumper.root

        # 注意: 过滤器/属性列表里不能出现 msExch* 名称 — 本工具的连接用
        # OFFLINE_AD_2012_R2 离线 schema (大域防卡死), ldap3 会对不在该 schema
        # 里的属性/类名抛 "invalid attribute type / invalid class"。
        # 这里临时关闭连接的 check_names, 属性用 ['*'] 拉全量后再从 entry 读取
        old_check_names = self.client.check_names
        self.client.check_names = False
        try:
            entries = paged_search(
                self.client, config_nc,
                '(objectClass=msExchRoleAssignment)',
                attributes=['*'],
            )
        finally:
            self.client.check_names = old_check_names
        if not entries:
            return assignments

        for entry in entries:
            try:
                role_link = str(entry['msExchRoleLink'].value)
                assignee_dn = str(entry['msExchUserLink'].value)
            except (KeyError, IndexError, TypeError):
                continue
            m = re.match(r'CN=([^,]+)', role_link, re.I)
            role_name = m.group(1) if m else role_link
            if role_name not in _EXCH_DANGEROUS_ROLES:
                continue

            # 解析受让人 (用户 或 组)
            try:
                self.client.search(
                    assignee_dn, '(objectClass=*)', search_scope=ldap3.BASE,
                    attributes=['sAMAccountName', 'objectClass',
                                'userAccountControl', 'name'],
                )
            except Exception:
                continue
            if not self.client.entries:
                continue
            assignee = self.client.entries[0]
            assignee_cn = assignee['name'].value or assignee_dn
            assignments.append((role_name, assignee_cn))

            label_prefix = 'Role:%s' % role_name
            classes = assignee['objectClass'].values or []
            if 'group' in classes:
                # 组受让人 → 递归展开成员, 标注经由哪个组
                members = paged_search(
                    self.client, self.domain_dumper.root,
                    '(memberof:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN,
                                           escape_filter_chars(assignee_dn)),
                    attributes=['sAMAccountName', 'distinguishedName',
                                'userAccountControl'],
                )
                for e2 in members:
                    self._add_user(users, e2, '%s (via %s)' % (label_prefix, assignee_cn))
            else:
                self._add_user(users, assignee, label_prefix)

        return assignments
