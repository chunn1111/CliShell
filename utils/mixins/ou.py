#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OU Management Mixin — 组织单位管理命令 (6 个)
"""

import re
import ldap3
import datetime
from ldap3.protocol.microsoft import security_descriptor_control

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import (
    parse_args, check_result,
    paged_search, print_table, print_table_capped,
)


def _ou_rows(entries):
    """OU entries → 表格行 [Name, Description, DN]"""
    rows = []
    for entry in entries:
        rows.append([
            entry['name'].value or '-',
            entry['description'].value or '-',
            entry.entry_dn,
        ])
    return rows


# gPLink 格式: [LDAP://<GPO DN>;<flags>]... flags: 0=启用 1=禁用 2=强制 3=禁用+强制
_GPO_LINK_RE = re.compile(r'LDAP://([^;\]]+);(\d+)')


def _fmt_ts(val):
    """格式化 AD 时间戳 (UTC → 本地时区)"""
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=datetime.timezone.utc)
        return val.astimezone().strftime('%Y-%m-%d %H:%M:%S')
    return str(val).split('+')[0]


class OUMixin:
    """OU Management 命令集"""

    # ── list_ous ──────────────────────────────────────────────
    def do_list_ous(self, line):
        """list_ous — 枚举所有 OU"""
        print_info("Enumerating OUs...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=organizationalUnit)',
            attributes=['name', 'distinguishedName', 'description'],
        )
        print_success("Found %d OU(s)" % len(entries))
        print_table_capped(['Name', 'Description', 'DN'], _ou_rows(entries),
                           tag='list_ous')

    # ── get_ou ────────────────────────────────────────────────
    def do_get_ou(self, line):
        """get_ou <ou_name> — 查看 OU 详情"""
        args = parse_args(line, 1, 1, "get_ou 'Domain Controllers'")

        from ldap3.utils.conv import escape_filter_chars
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=organizationalUnit)(name=%s))' % escape_filter_chars(args[0]),
            attributes=['*'],
        )
        if not self.client.entries:
            raise Exception("OU not found: %s" % args[0])
        entry = self.client.entries[0]

        rows = [['DN', entry.entry_dn]]
        for attr, label in [('description', 'Description'),
                            ('managedBy',   'ManagedBy'),
                            ('whenCreated', 'Created'),
                            ('whenChanged', 'Changed')]:
            try:
                val = entry[attr].value
            except KeyError:
                continue
            if val is None:
                continue
            if attr.startswith('when'):
                val = _fmt_ts(val)
            rows.append([label, str(val)])

        # gPOptions: 1 = 阻止策略继承
        try:
            gp_options = entry['gPOptions'].value
        except KeyError:
            gp_options = None
        if gp_options is not None:
            rows.append(['Block Inheritance',
                         'Yes' if int(gp_options) & 1 else 'No'])

        # gPLink: 解析 GPO 名称 + 链接状态
        try:
            gplink = entry['gPLink'].value
        except KeyError:
            gplink = None
        if gplink:
            links = _GPO_LINK_RE.findall(gplink)
            if links:
                names = self._resolve_gpo_names([dn for dn, _ in links])
                for gpo_dn, flags in links:
                    flag_list = []
                    if not (int(flags) & 1):
                        flag_list.append('Enabled')
                    else:
                        flag_list.append('Disabled')
                    if int(flags) & 2:
                        flag_list.append('Enforced')
                    rows.append(['GPO Link', '%s [%s]' % (
                        names.get(gpo_dn, gpo_dn), ', '.join(flag_list))])

        print_table(['Attribute', 'Value'], rows)

        # ── 直属成员 (one-level 子对象) ──
        children = paged_search(
            self.client, entry.entry_dn, '(objectClass=*)',
            attributes=['sAMAccountName', 'name', 'objectClass'],
            search_scope=ldap3.LEVEL,
        )
        if children:
            print()
            print_success("%d direct member(s):" % len(children))
            member_rows = []
            for e in children:
                classes = e['objectClass'].values or []
                member_rows.append([
                    e['sAMAccountName'].value or e['name'].value or '-',
                    classes[-1] if classes else '-',
                    e.entry_dn,
                ])
            member_rows.sort(key=lambda r: (r[1], r[0].lower()))
            print_table_capped(['Name', 'Type', 'DN'], member_rows,
                               tag='ou_members')

    def _resolve_gpo_names(self, gpo_dns):
        """批量解析 GPO DN → displayName"""
        from ldap3.utils.conv import escape_filter_chars
        import re as _re
        guids = []
        dn_map = {}
        for dn in gpo_dns:
            m = _re.match(r'CN=(\{[^}]+\})', dn, _re.I)
            if m:
                guids.append(m.group(1))
                dn_map[m.group(1).upper()] = dn
        if not guids:
            return {}
        filt = '(&(objectClass=groupPolicyContainer)(|%s))' % ''.join(
            '(name=%s)' % escape_filter_chars(g) for g in guids)
        names = {}
        try:
            self.client.search(self.domain_dumper.root, filt,
                               attributes=['name', 'displayName'])
            for e in self.client.entries:
                guid = str(e['name'].value).upper()
                if guid in dn_map:
                    names[dn_map[guid]] = e['displayName'].value or guid
        except Exception:
            pass
        return names

    # ── create_ou ─────────────────────────────────────────────
    def do_create_ou(self, line):
        """create_ou <ou_name> [parent_dn] — 创建 OU"""
        args = parse_args(line, 1, 2, "create_ou MyOU [DC=corp,DC=local]")

        ou_name = args[0]
        parent = args[1] if len(args) > 1 else self.domain_dumper.root
        ou_dn = 'OU=%s,%s' % (ou_name, parent)

        print_info("Creating OU: %s" % ou_dn)
        res = self.client.add(ou_dn, ['top', 'organizationalUnit'], {'ou': ou_name})
        if not res:
            raise Exception("Failed: %s" % self.client.result.get('description', ''))
        print_success("OU created: %s" % ou_dn)

    # ── delete_ou ─────────────────────────────────────────────
    def do_delete_ou(self, line):
        """delete_ou <ou_dn> — 删除 OU (必须为空)"""
        args = parse_args(line, 1, 1, "delete_ou OU=MyOU,DC=corp,DC=local")

        dn = args[0]
        if '=' not in dn:
            # 如果只给了名称，尝试查找
            from ldap3.utils.conv import escape_filter_chars
            self.client.search(
                self.domain_dumper.root,
                '(&(objectClass=organizationalUnit)(name=%s))' % escape_filter_chars(dn),
                attributes=['distinguishedName'],
            )
            if not self.client.entries:
                raise Exception("OU not found: %s" % dn)
            dn = self.client.entries[0].entry_dn

        print_info("Deleting OU: %s" % dn)
        self.client.delete(dn)
        check_result(self.client, "OU deleted")

    # ── move_object ───────────────────────────────────────────
    def do_move_object(self, line):
        """move_object <object_dn> <target_ou> — 移动对象到 OU"""
        args = parse_args(line, 2, 2, "move_object CN=jsmith,CN=Users,DC=corp,DC=local OU=NewOU,DC=corp,DC=local")

        object_dn = args[0]
        target_ou = args[1]

        # 提取 RDN 用于 modify_dn
        rdn = object_dn.split(',')[0]
        rdn_attr, _, rdn_val = rdn.partition('=')

        print_info("Moving %s → %s" % (object_dn, target_ou))
        self.client.modify_dn(object_dn, '%s=%s' % (rdn_attr, rdn_val), new_superior=target_ou)
        check_result(self.client, "Object moved successfully")

    # ── ou_acl ────────────────────────────────────────────────
    def do_ou_acl(self, line):
        """ou_acl <ou_name> — 查看 OU 的 ACL"""
        args = parse_args(line, 1, 1, "ou_acl 'Domain Controllers'")

        from ldap3.utils.conv import escape_filter_chars
        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=organizationalUnit)(name=%s))' % escape_filter_chars(args[0]),
            attributes=['nTSecurityDescriptor'],
            controls=controls,
        )
        if not self.client.entries:
            raise Exception("OU not found: %s" % args[0])

        from impacket.ldap import ldaptypes
        entry = self.client.entries[0]
        try:
            sd_data = entry['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

            print_info("OU: %s" % entry.entry_dn)
            print_info("Owner: %s" % sd['OwnerSid'].formatCanonical())
            print_info("DACL ACEs:")

            for i, ace in enumerate(sd['Dacl'].aces):
                try:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    mask = ace['Ace']['Mask']['Mask']
                    ace_type = ace['AceType']
                    print_found("  [%d] Type=%s SID=%s Mask=0x%08x" % (i, ace_type, sid, mask))
                except Exception:
                    print_found("  [%d] (unable to parse ACE)" % i)
        except (IndexError, KeyError):
            print_warn("Unable to read security descriptor")
