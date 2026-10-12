#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Connection Mixin — 连接 / 会话命令 (start_tls, dump, get_laps_password, exit)

dump 命令整合全量域信息导出，输出 9 个 CSV 到 report/ 目录:
  users.csv / groups.csv / trusts.csv / gpo.csv / ou.csv
  privileged.csv / delegation.csv / acl.csv / dns.csv
"""

import os
import gc
import csv
import time
import ssl
import ldap3
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control

from utils.ui import print_info, print_success, print_error, print_found, print_warn
from utils.helpers import (
    parse_args, paged_search,
    LDAP_MATCHING_RULE_IN_CHAIN, ad_timestamp_to_str,
)


def _v(entry, attr, default=''):
    """安全读取 entry 属性值 (保证返回标量)"""
    try:
        val = entry[attr].value
        if val is None:
            return default
        # ldap3 某些属性返回 tuple/list，取第一个元素
        if isinstance(val, (tuple, list)):
            return val[0] if val else default
        return val
    except Exception:
        return default


def _vs(entry, attr):
    """安全读取 entry 属性值列表 (始终返回 list)"""
    try:
        vals = entry[attr].values
        return list(vals) if vals else []
    except Exception:
        return []


class ConnectionMixin:
    """Connection / Session 命令集"""

    # ── start_tls ─────────────────────────────────────────────
    def do_start_tls(self, line):
        """start_tls — 升级 LDAP → LDAPS (含 LDAPS 端口探测)"""
        if getattr(self.client, 'tls_started', False) or self.client.server.ssl:
            print_info("Already connected through a TLS channel.")
            print_info("  SSL: %s, StartTLS: %s" % (
                self.client.server.ssl,
                getattr(self.client, 'tls_started', False),
            ))
            return

        print_info("Sending StartTLS command...")
        if not self.client.start_tls():
            raise Exception("StartTLS failed")
        print_success("StartTLS succeeded — now using LDAPS!")

        # 探测 LDAPS 端口 636 是否也可用
        print_info("Probing LDAPS port 636...")
        try:
            test_server = ldap3.Server(
                self.client.server.host,
                port=636,
                use_ssl=True,
                get_info=ldap3.OFFLINE_AD_2012_R2,
                tls=ldap3.Tls(validate=ssl.CERT_NONE),
            )
            test_conn = ldap3.Connection(test_server, auto_bind=True)
            test_conn.unbind()
            print_success("LDAPS (port 636) is also available")
        except Exception:
            print_warn("LDAPS port 636 not available (StartTLS on 389 is your encrypted channel)")

    # ═══════════════════════════════════════════════════════════
    #  dump — 全量域信息导出
    # ═══════════════════════════════════════════════════════════

    def do_dump(self, line):
        """dump — 全量导出域信息到 report/*.csv (12 个文件)"""
        from utils.helpers import print_table

        report_dir = 'report'
        os.makedirs(report_dir, exist_ok=True)

        # (方法名, 文件名, 显示名)
        steps = [
            ('_dump_users',      'users.csv',      'Users'),
            ('_dump_computers',  'computers.csv',  'Computers'),
            ('_dump_groups',     'groups.csv',     'Groups'),
            ('_dump_trusts',     'trusts.csv',     'Trusts'),
            ('_dump_gpos',       'gpo.csv',        'GPO'),
            ('_dump_ous',        'ou.csv',         'OU'),
            ('_dump_privileged', 'privileged.csv', 'Privileged'),
            ('_dump_delegation', 'delegation.csv', 'Delegation'),
            ('_dump_acl',        'acl.csv',        'ACL'),
            ('_dump_dns',        'dns.csv',        'DNS'),
            ('_dump_adcs',       'adcs.csv',       'ADCS'),
            ('_dump_creatorsid', 'creatorsid.csv', 'CreatorSID'),
        ]

        results = []
        total = len(steps)

        for idx, (method_name, filename, label) in enumerate(steps, 1):
            print_info("[%d/%d] Dumping %s..." % (idx, total, label))
            try:
                count = getattr(self, method_name)(report_dir)
                results.append((filename, count, None))
                print_success("  -> %s (%d items)" % (filename, count))
            except Exception as e:
                results.append((filename, 0, str(e)))
                print_error("  -> %s FAILED: %s" % (filename, str(e)))
            gc.collect()
            time.sleep(0.3)

        # ── 汇总表格 ────────────────────────────────────────
        ok_count = sum(1 for _, _, err in results if err is None)
        total_items = sum(c for _, c, _ in results)
        print()
        print_success("Done! %d/%d files exported, %d total items" % (ok_count, total, total_items))
        print()
        rows = []
        for filename, count, err in results:
            rows.append([filename, str(count), 'ERROR: %s' % err if err else 'OK'])
        print_table(['File', 'Items', 'Status'], rows)
        print()

    # ── CSV 写入辅助 ──────────────────────────────────────────

    @staticmethod
    def _dump_csv(report_dir, filename, rows, fieldnames):
        """通用 CSV 写入: list[dict] → file, list 值转 ; 分隔字符串

        返回写入的行数，供 do_dump 汇总使用。
        """
        filepath = os.path.join(report_dir, filename)
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for row in rows:
                cleaned = {}
                for k in fieldnames:
                    v = row.get(k, '')
                    if isinstance(v, list):
                        cleaned[k] = '; '.join(str(x) for x in v)
                    elif v is None:
                        cleaned[k] = ''
                    else:
                        cleaned[k] = v
                writer.writerow(cleaned)
        return len(rows)

    # ── users.csv ─────────────────────────────────────────────

    def _dump_users(self, report_dir):
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer)))',
            attributes=['sAMAccountName', 'displayName', 'distinguishedName',
                        'description', 'mail', 'userAccountControl',
                        'memberOf', 'lastLogonTimestamp', 'pwdLastSet',
                        'whenCreated', 'adminCount'],
        )
        fields = ['sAMAccountName', 'displayName', 'dn', 'description', 'mail',
                  'UAC', 'disabled', 'locked', 'pwdNeverExpires', 'noPreauth',
                  'adminCount', 'memberOf', 'lastLogon', 'pwdLastSet', 'whenCreated']
        rows = []
        for e in entries:
            uac = _v(e, 'userAccountControl', 0)
            rows.append({
                'sAMAccountName': _v(e, 'sAMAccountName'),
                'displayName': _v(e, 'displayName'),
                'dn': e.entry_dn,
                'description': _v(e, 'description'),
                'mail': _v(e, 'mail'),
                'UAC': '0x%08x' % uac,
                'disabled': 'Yes' if uac & 0x0002 else 'No',
                'locked': 'Yes' if uac & 0x0010 else 'No',
                'pwdNeverExpires': 'Yes' if uac & 0x10000 else 'No',
                'noPreauth': 'Yes' if uac & 0x400000 else 'No',
                'adminCount': _v(e, 'adminCount', 0),
                'memberOf': _vs(e, 'memberOf'),
                'lastLogon': ad_timestamp_to_str(_v(e, 'lastLogonTimestamp')),
                'pwdLastSet': ad_timestamp_to_str(_v(e, 'pwdLastSet')),
                'whenCreated': str(_v(e, 'whenCreated')),
            })
        return self._dump_csv(report_dir, 'users.csv', rows, fields)

    # ── groups.csv ────────────────────────────────────────────

    def _dump_groups(self, report_dir):
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=group)',
            attributes=['sAMAccountName', 'description', 'distinguishedName',
                        'member', 'memberOf', 'adminCount'],
        )
        fields = ['sAMAccountName', 'description', 'dn', 'adminCount', 'members', 'memberOf']
        rows = []
        for e in entries:
            rows.append({
                'sAMAccountName': _v(e, 'sAMAccountName'),
                'description': _v(e, 'description'),
                'dn': e.entry_dn,
                'adminCount': _v(e, 'adminCount', 0),
                'members': _vs(e, 'member'),
                'memberOf': _vs(e, 'memberOf'),
            })
        return self._dump_csv(report_dir, 'groups.csv', rows, fields)

    # ── computers.csv ──────────────────────────────────────────

    def _dump_computers(self, report_dir):
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=computer)',
            attributes=['sAMAccountName', 'dNSHostName', 'distinguishedName',
                        'description', 'operatingSystem', 'operatingSystemVersion',
                        'userAccountControl', 'memberOf', 'lastLogonTimestamp',
                        'pwdLastSet', 'whenCreated', 'servicePrincipalName'],
        )
        fields = ['sAMAccountName', 'dNSHostName', 'dn', 'description',
                  'OS', 'UAC', 'disabled', 'locked', 'trustedForDelegation',
                  'memberOf', 'lastLogon', 'pwdLastSet', 'whenCreated', 'SPNs']
        rows = []
        for e in entries:
            uac = _v(e, 'userAccountControl', 0)
            rows.append({
                'sAMAccountName': _v(e, 'sAMAccountName'),
                'dNSHostName': _v(e, 'dNSHostName'),
                'dn': e.entry_dn,
                'description': _v(e, 'description'),
                'OS': ('%s %s' % (_v(e, 'operatingSystem'), _v(e, 'operatingSystemVersion'))).strip(),
                'UAC': '0x%08x' % uac,
                'disabled': 'Yes' if uac & 0x0002 else 'No',
                'locked': 'Yes' if uac & 0x0010 else 'No',
                'trustedForDelegation': 'Yes' if uac & 0x80000 else 'No',
                'memberOf': _vs(e, 'memberOf'),
                'lastLogon': ad_timestamp_to_str(_v(e, 'lastLogonTimestamp')),
                'pwdLastSet': ad_timestamp_to_str(_v(e, 'pwdLastSet')),
                'whenCreated': str(_v(e, 'whenCreated')),
                'SPNs': _vs(e, 'servicePrincipalName'),
            })
        return self._dump_csv(report_dir, 'computers.csv', rows, fields)

    # ── trusts.csv ────────────────────────────────────────────

    def _dump_trusts(self, report_dir):
        _TRUST_DIR = {0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional'}
        _TRUST_TYPE = {1: 'Downlevel', 2: 'Uplevel (AD)', 3: 'MIT Kerberos'}
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=trustedDomain)',
            attributes=['cn', 'flatName', 'trustDirection', 'trustType', 'trustAttributes'],
        )
        fields = ['targetDomain', 'flatName', 'trustDirection', 'trustType', 'trustAttributes']
        rows = []
        for e in self.client.entries:
            td = _v(e, 'trustDirection', 0)
            tt = _v(e, 'trustType', 0)
            rows.append({
                'targetDomain': _v(e, 'cn'),
                'flatName': _v(e, 'flatName'),
                'trustDirection': _TRUST_DIR.get(td, str(td)),
                'trustType': _TRUST_TYPE.get(tt, str(tt)),
                'trustAttributes': str(_v(e, 'trustAttributes', '')),
            })
        return self._dump_csv(report_dir, 'trusts.csv', rows, fields)

    # ── gpo.csv ───────────────────────────────────────────────

    def _dump_gpos(self, report_dir):
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'distinguishedName', 'gPCFileSysPath', 'versionNumber'],
        )
        fields = ['name', 'displayName', 'dn', 'path', 'version']
        rows = []
        for e in self.client.entries:
            rows.append({
                'name': _v(e, 'cn'),
                'displayName': _v(e, 'displayName'),
                'dn': e.entry_dn,
                'path': _v(e, 'gPCFileSysPath'),
                'version': str(_v(e, 'versionNumber', '')),
            })
        return self._dump_csv(report_dir, 'gpo.csv', rows, fields)

    # ── ou.csv ────────────────────────────────────────────────

    def _dump_ous(self, report_dir):
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=organizationalUnit)',
            attributes=['name', 'distinguishedName', 'description',
                        'managedBy', 'whenCreated', 'gPLink'],
        )
        fields = ['name', 'dn', 'description', 'managedBy', 'gPLink', 'whenCreated']
        rows = []
        for e in entries:
            rows.append({
                'name': _v(e, 'name'),
                'dn': e.entry_dn,
                'description': _v(e, 'description'),
                'managedBy': _v(e, 'managedBy'),
                'gPLink': _v(e, 'gPLink'),
                'whenCreated': str(_v(e, 'whenCreated')),
            })
        return self._dump_csv(report_dir, 'ou.csv', rows, fields)

    # ── privileged.csv ────────────────────────────────────────

    def _dump_privileged(self, report_dir):
        priv_groups = [
            'Domain Admins', 'Enterprise Admins', 'Administrators',
            'Schema Admins', 'Backup Operators', 'Account Operators',
            'DNSAdmins',
        ]
        fields = ['group', 'member', 'dn', 'UAC', 'disabled']
        rows = []
        seen_dn = set()  # 用于去重 adminCount=1 查询

        for gname in priv_groups:
            self.client.search(
                self.domain_dumper.root,
                '(&(objectClass=group)(sAMAccountName=%s))' % escape_filter_chars(gname),
                attributes=['distinguishedName'],
            )
            if not self.client.entries:
                continue
            gdn = self.client.entries[0].entry_dn

            members = paged_search(
                self.client, self.domain_dumper.root,
                '(memberof:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(gdn)),
                attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl'],
            )
            for m in members:
                uac = _v(m, 'userAccountControl', 0)
                seen_dn.add(m.entry_dn.lower())
                rows.append({
                    'group': gname,
                    'member': _v(m, 'sAMAccountName'),
                    'dn': m.entry_dn,
                    'UAC': '0x%08x' % uac,
                    'disabled': 'Yes' if uac & 0x0002 else 'No',
                })

        # adminCount=1 的对象 (受 AdminSDHolder 保护，可能已不在特权组中)
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(adminCount=1)(|(objectClass=user)(objectClass=computer)))',
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl'],
        )
        for e in entries:
            if e.entry_dn.lower() in seen_dn:
                continue  # 已在特权组中出现，不重复
            uac = _v(e, 'userAccountControl', 0)
            rows.append({
                'group': '(adminCount=1)',
                'member': _v(e, 'sAMAccountName'),
                'dn': e.entry_dn,
                'UAC': '0x%08x' % uac,
                'disabled': 'Yes' if uac & 0x0002 else 'No',
            })

        return self._dump_csv(report_dir, 'privileged.csv', rows, fields)

    # ── delegation.csv ────────────────────────────────────────

    def _dump_delegation(self, report_dir):
        from impacket.ldap import ldaptypes

        fields = ['accountName', 'dn', 'type', 'details']
        rows = []

        # 非约束委派 (用户 + 机器)
        for obj_filter in ['(objectClass=computer)',
                           '(&(objectClass=user)(!(objectClass=computer)))']:
            entries = paged_search(
                self.client, self.domain_dumper.root,
                '(&%s(userAccountControl:1.2.840.113556.1.4.803:=524288))' % obj_filter,
                attributes=['sAMAccountName', 'distinguishedName'],
            )
            for e in entries:
                rows.append({
                    'accountName': _v(e, 'sAMAccountName'),
                    'dn': e.entry_dn,
                    'type': 'Unconstrained',
                    'details': '',
                })

        # 约束委派
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(msDS-AllowedToDelegateTo=*)',
            attributes=['sAMAccountName', 'distinguishedName', 'msDS-AllowedToDelegateTo'],
        )
        for e in entries:
            services = _vs(e, 'msDS-AllowedToDelegateTo')
            rows.append({
                'accountName': _v(e, 'sAMAccountName'),
                'dn': e.entry_dn,
                'type': 'Constrained',
                'details': '; '.join(str(s) for s in services),
            })

        # RBCD
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
        )
        for e in entries:
            actors = []
            try:
                sd_data = e['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                for ace in sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        resolved = self._resolve_sid(sid)
                        actors.append('%s (%s)' % (resolved, sid) if resolved else sid)
                    except Exception:
                        pass
            except Exception:
                pass
            rows.append({
                'accountName': _v(e, 'sAMAccountName'),
                'dn': _v(e, 'distinguishedName') or e.entry_dn,
                'type': 'RBCD',
                'details': '; '.join(actors) if actors else '(empty)',
            })

        return self._dump_csv(report_dir, 'delegation.csv', rows, fields)

    # ── acl.csv ───────────────────────────────────────────────

    def _dump_acl(self, report_dir):
        from impacket.ldap import ldaptypes
        from impacket.uuid import string_to_bin

        controls = security_descriptor_control(sdflags=0x04)
        fields = ['targetObject', 'trusteeSID', 'trusteeName', 'edge']
        rows = []

        # ACL 边缘定义 — 与 find_interesting_acl 完全对齐
        _MASK_CTRL  = 0x00000100
        _MASK_WPROP = 0x00000020
        _MASK_RPROP = 0x00000010
        _MASK_SELF  = 0x00000008

        _GUID_FCP   = '00299570-246d-11d0-a768-00aa006e0529'
        _GUID_MEM   = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        _GUID_SPN   = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        _GUID_UAR   = '4c164200-20c0-11d0-a768-00aa006e0529'
        _GUID_LAPS  = '4c9928d7-d725-4fa6-a109-aba3ad8790e5'
        _GUID_GMSA  = 'e362ed86-b728-0842-b27d-2dea7a9df218'
        _REPL_GC    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        _REPL_GCA   = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

        # (edge_mask, edge_guid_bin_or_None, edge_label)
        # [Bugfix] GenericWrite 映射形态是 0x00020028, 0x00020094 是 GENERIC_READ (只读)
        edge_defs = [
            (0x000f01ff,   None,                              'GenericAll'),
            (0x00020028,   None,                              'GenericWrite'),
            (0x00040000,   None,                              'WriteDacl'),
            (0x00080000,   None,                              'WriteOwner'),
            (_MASK_CTRL,   None,                              'AllExtendedRights'),
            (_MASK_CTRL,   string_to_bin(_GUID_FCP),         'ForceChangePassword'),
            (_MASK_WPROP,  string_to_bin(_GUID_MEM),         'AddMember'),
            (_MASK_SELF,   string_to_bin(_GUID_MEM),         'AddSelf'),
            (_MASK_CTRL,   string_to_bin(_GUID_LAPS),        'ReadLAPSPassword'),
            (_MASK_CTRL,   string_to_bin(_GUID_GMSA),        'ReadGMSAPassword'),
            (_MASK_SELF,   string_to_bin(_GUID_SPN),         'WriteSPN'),
            (_MASK_WPROP,  string_to_bin(_GUID_UAR),         'WriteAccountRestrictions'),
        ]

        excluded = self._get_acl_exclusions()

        def _match_edges(ace):
            """匹配单条 ACE 的所有 BloodHound 边缘"""
            found = []
            try:
                mask = ace['Ace']['Mask']['Mask']
                is_obj = (ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)
                for edge_mask, edge_guid, edge_label in edge_defs:
                    if edge_guid is None:
                        # mask-based 边缘
                        if mask & edge_mask == edge_mask:
                            found.append(edge_label)
                    else:
                        # GUID-based 边缘
                        if is_obj and (mask & edge_mask):
                            try:
                                if ace['Ace']['ObjectType'] == edge_guid:
                                    found.append(edge_label)
                            except (KeyError, IndexError):
                                pass
            except Exception:
                pass
            return found

        # ── 扫描 user / computer / group ─────────────────────
        _CLASS_FILTERS = {
            'user': '(&(objectClass=user)(!(objectClass=computer)))',
            'computer': '(objectClass=computer)',
            'group': '(objectClass=group)',
        }

        for obj_class in ['user', 'computer', 'group']:
            entries = paged_search(
                self.client, self.domain_dumper.root,
                _CLASS_FILTERS[obj_class],
                attributes=['sAMAccountName', 'objectSid', 'nTSecurityDescriptor'],
                controls=controls,
            )
            for entry in entries:
                target = _v(entry, 'sAMAccountName')
                try:
                    target_sid = str(entry['objectSid'].value)
                except Exception:
                    target_sid = None

                try:
                    sd_data = entry['nTSecurityDescriptor'].raw_values[0]
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                except (IndexError, KeyError):
                    continue

                # 按 (target, sid) 合并所有边缘
                sid_edges = {}
                for ace in sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid in excluded or sid == target_sid:
                            continue
                        edges = _match_edges(ace)
                        if edges:
                            sid_edges.setdefault(sid, set()).update(edges)
                    except Exception:
                        continue

                for sid, edges in sid_edges.items():
                    resolved = self._resolve_sid(sid)
                    # GenericAll 隐含其他权限，只保留 GenericAll
                    if 'GenericAll' in edges:
                        edges = {'GenericAll'}
                    rows.append({
                        'targetObject': target,
                        'trusteeSID': sid,
                        'trusteeName': resolved or '',
                        'edge': '; '.join(sorted(edges)),
                    })

        # ── 扫描域对象 (DCSync 等) ───────────────────────────
        try:
            self.client.search(
                self.domain_dumper.root,
                '(objectCategory=domain)',
                attributes=['nTSecurityDescriptor'],
                controls=controls,
            )
            if self.client.entries:
                domain_sd_data = self.client.entries[0]['nTSecurityDescriptor'].raw_values[0]
                domain_sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=domain_sd_data)
                repl_gc_bin = string_to_bin(_REPL_GC)
                repl_gca_bin = string_to_bin(_REPL_GCA)

                # 按 SID 收集域级边缘 + DCSync 检测
                domain_sid_info = {}
                for ace in domain_sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid in excluded:
                            continue
                        mask = ace['Ace']['Mask']['Mask']
                        is_obj = (ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)

                        # 标准 BloodHound 边缘
                        edges = _match_edges(ace)

                        # DCSync: REPL_GET_CHANGES + REPL_GET_CHANGES_ALL
                        if is_obj and (mask & _MASK_CTRL):
                            try:
                                obj_type = ace['Ace']['ObjectType']
                                if obj_type == repl_gc_bin:
                                    domain_sid_info.setdefault(sid, {'edges': set(), 'gc': False, 'gca': False})
                                    domain_sid_info[sid]['gc'] = True
                                    continue  # 不重复记录为 AllExtendedRights
                                elif obj_type == repl_gca_bin:
                                    domain_sid_info.setdefault(sid, {'edges': set(), 'gc': False, 'gca': False})
                                    domain_sid_info[sid]['gca'] = True
                                    continue
                            except (KeyError, IndexError):
                                pass

                        if edges:
                            domain_sid_info.setdefault(sid, {'edges': set(), 'gc': False, 'gca': False})
                            domain_sid_info[sid]['edges'].update(edges)
                    except Exception:
                        continue

                domain_label = 'DC (%s)' % self._extract_domain(self.domain_dumper.root)
                for sid, info in domain_sid_info.items():
                    all_edges = set(info['edges'])
                    if info['gc'] and info['gca']:
                        all_edges.add('DCSync')
                    if 'GenericAll' in all_edges:
                        all_edges = {'GenericAll'}
                    if all_edges:
                        resolved = self._resolve_sid(sid)
                        rows.append({
                            'targetObject': domain_label,
                            'trusteeSID': sid,
                            'trusteeName': resolved or '',
                            'edge': '; '.join(sorted(all_edges)),
                        })
        except Exception:
            pass

        return self._dump_csv(report_dir, 'acl.csv', rows, fields)

    # ── dns.csv ───────────────────────────────────────────────

    def _dump_dns(self, report_dir):
        from utils.mixins.dns import _parse_dns_value, DNS_RECORD

        fields = ['zone', 'source', 'name', 'type', 'data', 'TTL']
        rows = []

        dns_paths = [
            ('Domain', 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.domain_dumper.root),
            ('Forest', 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % self.domain_dumper.root),
            ('Legacy', 'CN=MicrosoftDNS,CN=System,%s' % self.domain_dumper.root),
        ]

        for zone_label, dns_base in dns_paths:
            # 枚举区域
            try:
                self.client.search(
                    dns_base, '(objectClass=dnsZone)',
                    search_scope='LEVEL', attributes=['dc'],
                )
            except Exception:
                continue

            zones = [_v(e, 'dc') for e in self.client.entries if _v(e, 'dc')]

            for zone in zones:
                zone_dn = 'DC=%s,%s' % (zone, dns_base)
                try:
                    entries = paged_search(
                        self.client, zone_dn,
                        '(objectClass=dnsNode)',
                        attributes=['name', 'dnsRecord', 'dNSTombstoned'],
                        search_scope='LEVEL',
                    )
                except Exception:
                    continue

                for entry in entries:
                    record_name = _v(entry, 'name') or '@'

                    # 跳过 tombstone
                    try:
                        if entry['dNSTombstoned'].value:
                            continue
                    except Exception:
                        pass

                    try:
                        raw_records = entry['dnsRecord'].raw_values
                    except (KeyError, TypeError):
                        continue

                    for raw in raw_records:
                        try:
                            dr = DNS_RECORD(raw)
                            if dr['Type'] == 0:
                                continue
                            rtype, value = _parse_dns_value(raw)
                            rows.append({
                                'zone': zone,
                                'source': zone_label,
                                'name': record_name if record_name != '@' else zone,
                                'type': rtype,
                                'data': value,
                                'TTL': str(dr['TtlSeconds']),
                            })
                        except Exception:
                            rows.append({
                                'zone': zone,
                                'source': zone_label,
                                'name': record_name,
                                'type': '?',
                                'data': '(parse error)',
                                'TTL': '',
                            })

        return self._dump_csv(report_dir, 'dns.csv', rows, fields)

    # ── adcs.csv ───────────────────────────────────────────────

    def _dump_adcs(self, report_dir):
        config_dn = self._get_config_dn()
        if not config_dn:
            return self._dump_csv(report_dir, 'adcs.csv', [], [])

        # 查询企业 CA 和证书模板
        cas = self._query_enterprise_cas(config_dn)
        templates = self._query_cert_templates(config_dn)

        # 构建 模板→CA 反向映射 (模板被哪些 CA 发布)
        tpl_to_cas = {}
        for ca in cas:
            for tpl_name in ca['templates']:
                tpl_to_cas.setdefault(tpl_name, []).append(ca['caName'])

        fields = ['type', 'name', 'displayName', 'dNSHostName', 'ip',
                  'schemaVersion', 'enrollmentFlags', 'subjectNameFlags',
                  'ekus', 'vulnerable', 'publishedTo', 'details']
        rows = []

        # Enterprise CA 行
        for ca in cas:
            rows.append({
                'type': 'EnterpriseCA',
                'name': ca['caName'],
                'displayName': '',
                'dNSHostName': ca['dNSHostName'],
                'ip': ca['ip'],
                'schemaVersion': '',
                'enrollmentFlags': '',
                'subjectNameFlags': '',
                'ekus': '',
                'vulnerable': '',
                'publishedTo': ca['templates'],
                'details': 'templates=%d' % len(ca['templates']),
            })

        # Template 行
        for tpl in templates:
            published_by = tpl_to_cas.get(tpl['name'], [])
            rows.append({
                'type': 'Template',
                'name': tpl['name'],
                'displayName': tpl['displayName'],
                'dNSHostName': '',
                'ip': '',
                'schemaVersion': tpl['schemaVersion'],
                'enrollmentFlags': tpl['enrollmentFlags'],
                'subjectNameFlags': tpl['subjectNameFlags'],
                'ekus': tpl['ekus'],
                'vulnerable': 'Yes' if tpl['vulnerable'] else 'No',
                'publishedTo': published_by,
                'details': 'ESC1' if tpl['vulnerable'] else '',
            })

        return self._dump_csv(report_dir, 'adcs.csv', rows, fields)

    # ── creatorsid.csv ──────────────────────────────────────────

    def _dump_creatorsid(self, report_dir):
        """导出机器账户的 CreatorSID — 域用户与被他拉入域的机器的关系"""
        from impacket.ldap import ldaptypes

        fields = ['computer', 'computerDN', 'creatorSID', 'creatorName']
        rows = []

        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=computer)',
            attributes=['sAMAccountName', 'distinguishedName', 'mS-DS-CreatorSID'],
        )

        for e in entries:
            raw_sid = _v(e, 'mS-DS-CreatorSID')
            if not raw_sid:
                continue
            # SID 可能是 bytes 或已解析的字符串
            if isinstance(raw_sid, bytes):
                try:
                    sid_obj = ldaptypes.LDAP_SID()
                    sid_obj.fromString(raw_sid)
                    creator_sid = sid_obj.formatCanonical()
                except Exception:
                    creator_sid = raw_sid.hex()
            else:
                creator_sid = str(raw_sid)

            creator_name = self._resolve_sid(creator_sid) or ''
            rows.append({
                'computer': _v(e, 'sAMAccountName'),
                'computerDN': e.entry_dn,
                'creatorSID': creator_sid,
                'creatorName': creator_name,
            })

        return self._dump_csv(report_dir, 'creatorsid.csv', rows, fields)

    # ── get_laps_password ─────────────────────────────────────
    def do_get_laps_password(self, line):
        """get_laps_password <computer> — 获取 LAPS 本地管理员密码"""
        args = parse_args(line, 1, 1, "get_laps_password DC01$")

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        self.client.search(
            self.domain_dumper.root,
            '(sAMAccountName=%s)' % escape_filter_chars(computer_name),
            attributes=['ms-MCS-AdmPwd', 'ms-MCS-AdmPwdExpirationTime'],
        )
        if len(self.client.entries) != 1:
            raise Exception("Expected 1 result, got %d" % len(self.client.entries))

        computer = self.client.entries[0]
        print_found("Computer: %s" % computer.entry_dn)

        password = computer['ms-MCS-AdmPwd'].value
        if password:
            print_success("LAPS Password: %s" % password)
        else:
            print_error("Unable to read LAPS password (no permission or LAPS not configured)")
