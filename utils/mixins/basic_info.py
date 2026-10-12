#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic Info Mixin — 域基本信息命令 (1 个)

get_basic_info: 显示当前会话状态 + 域用户/机器数量统计
"""

import re
import datetime

from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_warn
from utils.helpers import (
    ad_timestamp_to_str, UAC, is_ldaps, paged_search, print_table,
)



class BasicInfoMixin:
    """域基本信息命令集"""

    # ── get_basic_info ────────────────────────────────────────
    def do_get_basic_info(self, line):
        """
        get_basic_info — 显示域基本信息、当前用户状态、用户/机器数量统计
        """
        domain = self._extract_domain(self.base_DN)

        # ── 1. 查询当前用户对象 ────────────────────────────────
        self.client.search(
            self.domain_dumper.root,
            '(sAMAccountName=%s)' % escape_filter_chars(self.username),
            attributes=[
                'distinguishedName', 'userAccountControl', 'adminCount',
                'pwdLastSet', 'accountExpires', 'memberOf',
                'lockoutTime', 'lastLogon', 'whenCreated',
            ],
        )
        user_entry = self.client.entries[0] if self.client.entries else None

        # ── 2. 查询域 SID + MQA + 密码策略 ─────────────────
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=domain)',
            attributes=['objectSid', 'ms-DS-MachineAccountQuota',
                        'pwdHistoryLength', 'minPwdAge'],
        )
        domain_sid = 'N/A'
        mqa = 'N/A'
        pwd_history = 'N/A'
        min_pwd_age = 'N/A'
        if self.client.entries:
            try:
                domain_sid = str(self.client.entries[0]['objectSid'].value)
                self.domain_sid = domain_sid
            except Exception:
                pass
            try:
                mqa = self.client.entries[0]['ms-DS-MachineAccountQuota'].value
                mqa = str(mqa) if mqa is not None else 'Not Set'
            except Exception:
                mqa = 'N/A'
            try:
                # pwdHistoryLength: 0 = 未开启 (不记住旧密码), >0 = 记住最近 N 个密码
                hist_len = self.client.entries[0]['pwdHistoryLength'].value
                if hist_len is None or int(hist_len) <= 0:
                    pwd_history = 'Disabled (remember 0)'
                else:
                    pwd_history = 'Enabled (remember last %d)' % int(hist_len)
            except Exception:
                pwd_history = 'N/A'
            try:
                # minPwdAge: ldap3 返回 timedelta (原始为负数 100ns 间隔) → 换算为天数
                # 0 = 可立即重复改密 (连续改 N+1 次即可绕过密码历史用回原密码)
                age_raw = self.client.entries[0]['minPwdAge'].value
                if age_raw is None:
                    min_pwd_age = 'N/A'
                else:
                    if isinstance(age_raw, datetime.timedelta):
                        days = abs(age_raw.total_seconds()) / 86400
                    else:
                        days = abs(int(age_raw)) / 10000000.0 / 86400
                    days_str = '%d' % days if days == int(days) else '%.1f' % days
                    min_pwd_age = '%s day(s)' % days_str
                    if days == 0:
                        min_pwd_age += ' (can change immediately — 密码历史可绕过)'
            except Exception:
                min_pwd_age = 'N/A'

        # ── 3. 查询所有域控制器 ──────────────────────────────
        try:
            self.client.search(
                self.domain_dumper.root,
                '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['sAMAccountName'],
            )
            dc_list = [e['sAMAccountName'].value for e in self.client.entries if e['sAMAccountName'].value]
        except Exception:
            dc_list = []

        # ── 4. 统计域用户数量 (分页查询) ──────────────────────
        print_info("Counting domain users...")
        user_entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer)))',
            attributes=['sAMAccountName'],
        )
        user_count = len(user_entries)

        # ── 5. 统计域机器数量 (分页查询) ──────────────────────
        print_info("Counting domain computers...")
        computer_entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=computer)',
            attributes=['sAMAccountName'],
        )
        computer_count = len(computer_entries)

        # ── 6. 查询用户 ACL 权限概要 ─────────────────────────
        acl_summary = self._get_user_acl_summary()

        # ══════════════════════════════════════════════════════
        #  构建表格行
        # ══════════════════════════════════════════════════════
        rows = []

        # 连接信息
        proto = 'LDAPS' if is_ldaps(self.client) else 'LDAP'
        rows.append(['User', self.username])
        rows.append(['Domain', '%s (%s)' % (domain, proto)])
        rows.append(['DC', self.dc_address])
        rows.append(['BaseDN', self.base_DN])
        rows.append(['Domain SID', domain_sid])
        if dc_list:
            rows.append(['All DCs [%d]' % len(dc_list), ', '.join(dc_list)])

        # 用户状态
        if user_entry:
            uac_val = user_entry['userAccountControl'].value or 0
            admin_count = user_entry['adminCount'].value or 0
            pwd_last = ad_timestamp_to_str(user_entry['pwdLastSet'].value)
            account_expires = user_entry['accountExpires'].value

            # 密码过期计算
            never_expire_int = 9223372036854775807
            is_never = False
            if account_expires is None or account_expires == 0:
                is_never = True
            elif isinstance(account_expires, int) and account_expires >= never_expire_int:
                is_never = True
            elif isinstance(account_expires, datetime.datetime):
                if account_expires.year <= 1601 or account_expires.year >= 9999:
                    is_never = True
            else:
                try:
                    is_never = int(account_expires) >= never_expire_int
                except (TypeError, ValueError):
                    pass

            if is_never:
                if uac_val & UAC['DONT_EXPIRE_PASSWORD']:
                    pwd_expires = 'Never (DONT_EXPIRE_PASSWORD)'
                else:
                    pwd_expires = 'Never (account policy)'
            elif isinstance(account_expires, datetime.datetime):
                pwd_expires = ad_timestamp_to_str(account_expires)
            else:
                pwd_expires = ad_timestamp_to_str(account_expires)

            # UAC 标志解析
            flags = []
            if uac_val & UAC['ACCOUNTDISABLE']:
                flags.append('DISABLED')
            if uac_val & UAC['LOCKOUT']:
                flags.append('LOCKED')
            if uac_val & UAC['DONT_EXPIRE_PASSWORD']:
                flags.append('PWD_NEVER_EXPIRE')
            if uac_val & UAC['DONT_REQ_PREAUTH']:
                flags.append('NO_PREAUTH')
            if uac_val & UAC['TRUSTED_FOR_DELEGATION']:
                flags.append('TRUSTED_FOR_DELEGATION')
            if uac_val & UAC['NOT_DELEGATED']:
                flags.append('NOT_DELEGATED')
            if uac_val & UAC['SMARTCARD_REQUIRED']:
                flags.append('SMARTCARD')
            flags_str = ', '.join(flags) if flags else 'NORMAL'

            rows.append(['UAC', '0x%08x (%s)' % (uac_val, flags_str)])
            rows.append(['adminCount', str(admin_count)])
            rows.append(['pwdLastSet', pwd_last])
            rows.append(['Pwd Expires', pwd_expires])
        else:
            rows.append(['User Info', '(unable to query)'])

        rows.append(['MachineAccountQuota', mqa])
        rows.append(['Pwd History Policy', pwd_history])
        rows.append(['Min Pwd Age', min_pwd_age])

        # 域统计
        rows.append(['Domain Users', str(user_count)])
        rows.append(['Domain Computers', str(computer_count)])

        # 组成员关系
        if user_entry:
            groups = user_entry['memberOf'].values or []
            group_names = []
            for g in groups:
                cn_match = re.match(r'CN=([^,]+)', g, re.I)
                group_names.append(cn_match.group(1) if cn_match else g)
            groups_str = ', '.join(group_names)
            rows.append(['Groups [%d]' % len(group_names), groups_str])
        else:
            rows.append(['Groups', '(unable to query)'])

        # OU 信息
        if user_entry:
            user_dn = user_entry.entry_dn
            ou_parts = re.findall(r'OU=([^,]+)', user_dn, re.I)
            ou_str = ' > '.join(ou_parts) if ou_parts else '(root)'
            rows.append(['User OU', ou_str])

        # ACL 概要
        if acl_summary:
            rows.append(['ACL Privs', ', '.join(acl_summary)])
        else:
            rows.append(['ACL Privs', '(standard user)'])

        # 打印横排表格
        print()
        print_table(['Property', 'Value'], rows)
        print()
