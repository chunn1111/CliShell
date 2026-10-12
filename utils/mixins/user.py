#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
User Management Mixin — 用户管理命令 (4 个)
"""

import re
import string
import random
import ldap3
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM

from utils.ui import print_info, print_success, print_error, print_warn, print_found
from utils.helpers import (
    parse_args, require_ldaps, check_result,
    get_dn, get_entry, ad_timestamp_to_str,
    LDAP_MATCHING_RULE_IN_CHAIN, UAC,
    paged_search,
)
from ldap3.utils.conv import escape_filter_chars

# 对齐输出的标签列宽
_LABEL_W = 20


class UserMixin:
    """User Management 命令集"""

    # ── add_user ──────────────────────────────────────────────
    def do_add_user(self, line):
        """add_user <user> [ou] — 创建用户 (需要 LDAPS)"""
        args = parse_args(line, 1, 2, "add_user jsmith [OU=CustomOU,DC=corp,DC=local]")
        require_ldaps(self.client)

        new_user = args[0]
        parent_dn = args[1] if len(args) > 1 else 'CN=Users,%s' % self.domain_dumper.root
        new_password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        new_user_dn = 'CN=%s,%s' % (new_user, parent_dn)
        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % self.domain_dumper.root,
            'distinguishedName': new_user_dn,
            'cn': new_user,
            'sn': new_user,
            'givenName': new_user,
            'displayName': new_user,
            'name': new_user,
            'userAccountControl': 512,  # NORMAL_ACCOUNT
            'accountExpires': '0',
            'sAMAccountName': new_user,
            'unicodePwd': '"{}"'.format(new_password).encode('utf-16-le'),
        }

        print_info("Creating user in: %s" % parent_dn)
        res = self.client.add(new_user_dn, ['top', 'person', 'organizationalPerson', 'user'], ucd)
        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                raise Exception("Server denied. Try LDAPS (start_tls or port 636).")
            raise Exception("Failed: %s" % self.client.result.get('description', ''))
        print_success("Created user: %s / Password: %s" % (new_user, new_password))

    # ── delete_user ───────────────────────────────────────────
    def do_delete_user(self, line):
        """delete_user <user> — 删除用户"""
        args = parse_args(line, 1, 1, "delete_user jsmith")
        dn = get_dn(self.client, self.domain_dumper, args[0])
        if not dn:
            raise Exception("User not found: %s" % args[0])

        print_info("Deleting user: %s" % dn)
        self.client.delete(dn)
        check_result(self.client, "Deleted user %s" % args[0])

    # ── get_user ──────────────────────────────────────────────
    def do_get_user(self, line):
        """get_user <user> — 查看用户完整详情 (含组/登录/密码)"""
        args = parse_args(line, 1, 1, "get_user jsmith")
        entry = get_entry(self.client, self.domain_dumper, args[0])
        if not entry:
            raise Exception("User not found: %s" % args[0])

        # ── 安全属性读取 ──
        def _attr(name, default=''):
            try:
                v = entry[name].value
                return v if v is not None else default
            except (KeyError, IndexError):
                return default

        def _fmt_ts(ts):
            if not ts:
                return 'Never'
            s = ad_timestamp_to_str(ts)
            if '1601' in s:
                return 'Never'
            s = str(s)
            # 去掉时区后缀 +00:00
            if '+' in s:
                s = s[:s.rfind('+')]
            # 去掉微秒 .612120
            if '.' in s:
                s = s[:s.rfind('.')]
            return s.strip()

        sam = _attr('sAMAccountName', '?')
        dn = entry.entry_dn
        upn = _attr('userPrincipalName')
        sid = str(_attr('objectSid', ''))
        display_name = _attr('displayName')
        uac_val = int(_attr('userAccountControl', 0) or 0)
        admin_count = _attr('adminCount', 0) or 0
        when_created = _attr('whenCreated', '')
        when_changed = _attr('whenChanged', '')

        spns = []
        try:
            spns = entry['servicePrincipalName'].values or []
        except (KeyError, IndexError):
            pass

        # ── UAC 标志解析 ──
        flags = []
        if uac_val & UAC['ACCOUNTDISABLE']:
            flags.append('DISABLED')
        if uac_val & UAC['LOCKOUT']:
            flags.append('LOCKED')
        if uac_val & UAC['PASSWD_NOTREQD']:
            flags.append('PWD_NOTREQD')
        if uac_val & UAC['DONT_EXPIRE_PASSWORD']:
            flags.append('PWD_NEVER_EXPIRE')
        if uac_val & UAC['DONT_REQ_PREAUTH']:
            flags.append('NO_PREAUTH')
        if uac_val & UAC['SMARTCARD_REQUIRED']:
            flags.append('SMARTCARD')
        if uac_val & UAC['TRUSTED_FOR_DELEGATION']:
            flags.append('TRUSTED_FOR_DELEGATION')
        if uac_val & UAC['NOT_DELEGATED']:
            flags.append('NOT_DELEGATED')
        flags_str = ', '.join(flags) if flags else 'NORMAL'
        enabled = 'No' if uac_val & UAC['ACCOUNTDISABLE'] else 'Yes'

        # ── Groups ──
        # 注意: 每一步独立容错 — memberOf 属性缺失 (用户无直接组) 是正常情况,
        # 不能让整个块静默跳过 (否则 primary group / 嵌套组都丢了)
        member_of = []
        pgid = None
        primary_group = None
        recursive_names = set()
        direct_names = []
        nested_names = []

        try:
            member_of = entry['memberOf'].values or []
        except (KeyError, IndexError):
            pass
        try:
            pgid = entry['primaryGroupID'].value
        except (KeyError, IndexError):
            pass

        if pgid is not None:
            try:
                primary_group, _ = self._resolve_pgid(pgid)
            except Exception:
                primary_group = None

        # 递归查询所有组 (含嵌套)
        try:
            rec_entries = paged_search(
                self.client, self.domain_dumper.root,
                '(member:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(dn)),
                attributes=['sAMAccountName'],
            )
            for e in rec_entries:
                name = e['sAMAccountName'].value
                if name:
                    recursive_names.add(name)
        except Exception:
            pass

        for g in member_of:
            cn_match = re.match(r'CN=([^,]+)', g, re.I)
            direct_names.append(cn_match.group(1) if cn_match else g)

        if primary_group:
            direct_names.append(primary_group)
            recursive_names.add(primary_group)

        nested_names = sorted(recursive_names - set(direct_names))

        # ── 构建表格 ──
        # 主表: 横排 key-value
        pwd_ts = _attr('pwdLastSet', 0) or 0
        never_expires = bool(uac_val & UAC['DONT_EXPIRE_PASSWORD'])

        header = ['Username', 'Enabled', 'adminCnt', 'UAC', 'lastLogon', 'pwdLastSet', 'Expires']
        row = [
            sam,
            enabled,
            str(admin_count),
            flags_str,
            _fmt_ts(_attr('lastLogon', 0) or 0),
            _fmt_ts(pwd_ts),
            'Never' if never_expires else 'Policy',
        ]

        # 计算列宽
        col_lens = [max(len(h), len(r)) for h, r in zip(header, row)]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        # 打印表头
        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        print(fmt.format(*row))

        # ── 附加信息 (多值字段) ──
        if direct_names or nested_names:
            print()
            if direct_names:
                print_info("Groups (Direct): %s" % ', '.join(direct_names))
            if nested_names:
                print_info("Groups (Nested): %s" % ', '.join(nested_names))
            print_info("Groups Total:    %d" % len(recursive_names))

        if spns:
            print()
            for spn in spns:
                print_found("SPN: %s" % spn)

        # DN / SID 等长字段单独一行
        print()
        print_found("DN:  %s" % dn)
        # OU / 容器信息 (父级 DN)
        if ',' in dn:
            print_found("OU:  %s" % dn.split(',', 1)[1])
        if upn:
            print_found("UPN: %s" % upn)
        print_found("SID: %s" % sid)
        # 登录脚本
        logon_script = _attr('scriptPath')
        if logon_script:
            print_found("Logon Script: %s" % logon_script)

    # ── unlock_user ───────────────────────────────────────────
    def do_unlock_user(self, line):
        """unlock_user <user> — 解锁用户 (清除 lockoutTime)"""
        args = parse_args(line, 1, 1, "unlock_user jsmith")
        dn = get_dn(self.client, self.domain_dumper, args[0])
        if not dn:
            raise Exception("User not found: %s" % args[0])

        print_info("Unlocking user: %s" % args[0])
        self.client.modify(dn, {'lockoutTime': (ldap3.MODIFY_REPLACE, [0])})
        check_result(self.client, "User %s unlocked" % args[0])

    # ── 内部辅助 ──────────────────────────────────────────────

    def _resolve_pgid(self, pgid):
        """将 primaryGroupID 解析为 (sAMAccountName, DN)
        primaryGroupToken 是构造属性, 不能用于 LDAP 过滤器,
        改用 domain SID + RID 查 objectSid"""
        domain_sid = getattr(self, 'domain_sid', '')
        if not domain_sid:
            try:
                self.client.search(
                    self.domain_dumper.root, '(objectClass=domain)',
                    attributes=['objectSid'],
                )
                if self.client.entries:
                    domain_sid = str(self.client.entries[0]['objectSid'].value)
                    self.domain_sid = domain_sid
            except Exception:
                pass
        if not domain_sid:
            return None, None
        self.client.search(
            self.domain_dumper.root,
            '(objectSid=%s-%d)' % (domain_sid, int(pgid)),
            attributes=['sAMAccountName', 'distinguishedName'],
        )
        if self.client.entries:
            g = self.client.entries[0]
            return g['sAMAccountName'].value, g.entry_dn
        return None, None
