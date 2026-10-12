#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Info Mixin — 域信息 + Trust + RODC 命令 (10 个)
"""

from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn, print_header, print_error
from utils.helpers import TRUST_DIRECTION, TRUST_TYPE, paged_search, print_table


class DomainInfoMixin:
    """Domain Info + Trust 命令集"""

    # ── domain_trusts ─────────────────────────────────────────
    def do_domain_trusts(self, line):
        """domain_trusts — 域信任关系"""
        print_info("Querying domain trusts...")
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=trustedDomain)',
            attributes=['cn', 'trustAttributes', 'trustDirection', 'trustType', 'flatName'],
        )
        entries = self.client.entries
        if not entries:
            print_warn("No domain trusts found")
            return

        print_success("Found %d trust(s)" % len(entries))
        for entry in entries:
            name = entry['cn'].value
            direction = TRUST_DIRECTION.get(int(entry['trustDirection'].value or 0), 'Unknown')
            ttype = TRUST_TYPE.get(int(entry['trustType'].value or 0), 'Unknown')
            flat = entry['flatName'].value or ''
            attrs = int(entry['trustAttributes'].value or 0)

            print_found("%s (%s) — Direction: %s, Type: %s, Attributes: 0x%x" % (
                name, flat, direction, ttype, attrs
            ))

    # ── domain_sites ──────────────────────────────────────────
    def do_domain_sites(self, line):
        """domain_sites — AD Sites"""
        # Sites 在 Configuration NC 下
        config_dn = self._get_config_dn()
        print_info("Searching AD Sites...")
        self.client.search(
            config_dn,
            '(objectClass=site)',
            attributes=['cn', 'description', 'distinguishedName'],
        )
        entries = self.client.entries
        print_success("Found %d site(s)" % len(entries))
        for entry in self.client.entries:
            print_found("%s — %s" % (entry['cn'].value, entry.entry_dn))

    # ── domain_subnets ────────────────────────────────────────
    def do_domain_subnets(self, line):
        """domain_subnets — AD Subnets"""
        config_dn = self._get_config_dn()
        print_info("Searching AD Subnets...")
        self.client.search(
            config_dn,
            '(objectClass=subnet)',
            attributes=['cn', 'siteObject', 'description', 'location'],
        )
        entries = self.client.entries
        print_success("Found %d subnet(s)" % len(entries))
        for entry in self.client.entries:
            site = entry['siteObject'].value or 'N/A'
            print_found("%s → Site: %s" % (entry['cn'].value, site))

    # ── forest_info ───────────────────────────────────────────
    def do_forest_info(self, line):
        """forest_info — Forest 信息"""
        config_dn = self._get_config_dn()
        # Forest 信息从 Partitions 容器获取
        partitions_dn = 'CN=Partitions,%s' % config_dn
        self.client.search(
            partitions_dn,
            '(objectClass=crossRef)',
            attributes=['cn', 'nCName', 'dnsRoot', 'netbiosName'],
        )
        print_header("Forest Info")
        for entry in self.client.entries:
            nc = entry['nCName'].value or ''
            # 只显示域 NC (不是 Schema/Config)
            if 'DC=' in nc and 'CN=' not in nc.split('DC=')[0]:
                print_found("%s — %s (%s)" % (
                    entry['dnsRoot'].value,
                    entry['netbiosName'].value or '',
                    nc,
                ))

    # ── forest_domains ────────────────────────────────────────
    def do_forest_domains(self, line):
        """forest_domains — Forest 下的所有域"""
        config_dn = self._get_config_dn()
        partitions_dn = 'CN=Partitions,%s' % config_dn
        self.client.search(
            partitions_dn,
            '(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))',
            # systemFlags & 3 = domain NC
            attributes=['cn', 'dnsRoot', 'nCName', 'netbiosName'],
        )
        entries = self.client.entries
        print_success("Found %d domain(s) in forest" % len(entries))
        for entry in self.client.entries:
            print_found("%s (%s) — %s" % (
                entry['dnsRoot'].value,
                entry['netbiosName'].value or '',
                entry['nCName'].value,
            ))

    # ── trusts (别名) ────────────────────────────────────────
    def do_trusts(self, line):
        """trusts — 信任关系 (同 domain_trusts)"""
        self.do_domain_trusts(line)

    # ── trust_map ─────────────────────────────────────────────
    def do_trust_map(self, line):
        """trust_map — 信任拓扑"""
        print_info("Building trust map...")
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=trustedDomain)',
            attributes=['cn', 'flatName', 'trustDirection', 'trustType', 'trustAttributes'],
        )
        entries = self.client.entries
        if not entries:
            print_warn("No trusts found")
            return

        from utils.helpers import get_domain_name
        current_domain = get_domain_name(self.domain_dumper.root)
        print_header("Trust Map — %s" % current_domain)

        for entry in self.client.entries:
            target = entry['cn'].value
            flat = entry['flatName'].value or ''
            direction = TRUST_DIRECTION.get(entry['trustDirection'].value, '?')
            attrs = int(entry['trustAttributes'].value or 0)

            # 解析信任属性标志
            flags = []
            if attrs & 0x00000001:
                flags.append('NonTransitive')
            if attrs & 0x00000002:
                flags.append('UpLevel')
            if attrs & 0x00000004:
                flags.append('Quarantined')
            if attrs & 0x00000008:
                flags.append('ForestTransitive')
            if attrs & 0x00000020:
                flags.append('CrossOrganizational')
            if attrs & 0x00000040:
                flags.append('WithinForest')
            if attrs & 0x00000080:
                flags.append('TreatAsExternal')
            if attrs & 0x00000200:
                flags.append('UsesRC4')

            flag_str = ', '.join(flags) if flags else 'None'
            print_found("  %s (%s) [%s] Attrs: %s" % (target, flat, direction, flag_str))

    # ── external_trusts ───────────────────────────────────────
    def do_external_trusts(self, line):
        """external_trusts — 外部信任"""
        print_info("Searching external trusts...")
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=trustedDomain)',
            attributes=['cn', 'flatName', 'trustDirection', 'trustAttributes'],
        )
        found = False
        for entry in self.client.entries:
            attrs = int(entry['trustAttributes'].value or 0)
            # 外部信任: 不是 WithinForest (0x20) 且不是 ForestTransitive (0x08)
            # 注: 0x40 是 TREAT_AS_EXTERNAL, 别混淆
            if not (attrs & 0x00000020) and not (attrs & 0x00000008):
                direction = TRUST_DIRECTION.get(entry['trustDirection'].value, '?')
                print_found("%s (%s) [%s]" % (entry['cn'].value, entry['flatName'].value or '', direction))
                found = True
        if not found:
            print_warn("No external trusts found")

    # ── forest_trusts ─────────────────────────────────────────
    def do_forest_trusts(self, line):
        """forest_trusts — Forest 信任"""
        print_info("Searching forest trusts...")
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=trustedDomain)',
            attributes=['cn', 'flatName', 'trustDirection', 'trustAttributes'],
        )
        forest, within, external = [], [], []
        for entry in self.client.entries:
            attrs = int(entry['trustAttributes'].value or 0)
            direction = TRUST_DIRECTION.get(entry['trustDirection'].value, '?')
            name = "%s (%s) [%s]" % (entry['cn'].value, entry['flatName'].value or '', direction)
            if attrs & 0x00000008:        # FOREST_TRANSITIVE: 跨林信任
                forest.append(name)
            elif attrs & 0x00000020:      # WITHIN_FOREST: 林内
                within.append(name)
            else:                         # 其余: 外部/隔离
                external.append(name + ' (quarantined)' if attrs & 0x4 else name)

        if forest:
            print_success("Cross-forest trust(s):")
            for n in forest:
                print_found(n)
        else:
            print_warn("No cross-forest trusts (trustAttributes & FOREST_TRANSITIVE)")
        if within:
            print_info("Within-forest (同林) trust(s) — 用 forest_domains 看全林结构:")
            for n in within:
                print_found(n)
        if external:
            print_info("External/quarantined trust(s):")
            for n in external:
                print_found(n)

    # ── get_rodc ──────────────────────────────────────────────

    # RODC 专属属性 (某些域 schema 可能不存在，需按需请求)
    _RODC_EXTRA_ATTRS = [
        'msDS-ManagedBy', 'msDS-KrbTgtLink',
        'msDS-RevealOnDemandGroup', 'msDS-NeverRevealGroup',
        'msDS-RevealedList',
    ]
    # 基础属性 (所有域都支持)
    _RODC_BASIC_ATTRS = [
        'sAMAccountName', 'dNSHostName', 'operatingSystem', 'whenCreated',
    ]

    def do_get_rodc(self, line):
        """
        get_rodc [rodc_name] — RODC 信息搜集

        无参数: 列出域内所有 RODC 概要 (名称/DNS/OS)
        有参数: 指定 RODC 的详细信息 (密码策略 + 缓存密码 + krbtgt + 管理员)
        """
        target = line.strip()

        # 先用基础属性查 RODC (避免 schema 不支持 RODC 属性时报错)
        print_info("Querying RODC computers...")
        try:
            entries = paged_search(
                self.client, self.domain_dumper.root,
                '(&(objectClass=computer)(msDS-IsRODC=TRUE))',
                attributes=self._RODC_BASIC_ATTRS,
            )
        except Exception as e:
            # msDS-IsRODC 属性可能不在 schema 中 (老域 / 未部署 RODC)
            if 'attribute' in str(e).lower():
                print_warn("No RODCs found (msDS-IsRODC attribute not in schema)")
            else:
                print_error(str(e))
            return

        if not entries:
            print_warn("No RODCs found in domain")
            return

        if target:
            # ── 详情模式: 找匹配的 RODC，再查完整属性 ──
            matched = [e for e in entries
                       if e['sAMAccountName'].value.lower() == target.lower()]
            if not matched:
                print_error("RODC '%s' not found" % target)
                return
            sam = matched[0]['sAMAccountName'].value
            detail = self._query_rodc_detail(sam)
            if detail:
                self._print_rodc_detail(detail)
            else:
                # 回退: 用基础信息输出
                print_info("RODC: %s" % sam)
                print_warn("Could not retrieve RODC-specific attributes")
        else:
            # ── 列表模式 ──
            print_success("Found %d RODC(s)" % len(entries))
            print()
            rows = []
            for entry in entries:
                sam = entry['sAMAccountName'].value
                dns = entry['dNSHostName'].value or '-'
                os_ = entry['operatingSystem'].value or '-'
                rows.append([sam, dns, os_])
            print_table(['Computer', 'DNS', 'OS'], rows)

    def _query_rodc_detail(self, sam_name):
        """查询单个 RODC 的完整属性，schema 不支持则返回 None"""
        try:
            self.client.search(
                self.domain_dumper.root,
                '(&(objectClass=computer)(sAMAccountName=%s))'
                % escape_filter_chars(sam_name),
                attributes=self._RODC_BASIC_ATTRS + self._RODC_EXTRA_ATTRS,
            )
            if self.client.entries:
                return self.client.entries[0]
        except Exception:
            pass
        return None

    def _print_rodc_detail(self, entry):
        """输出单个 RODC 的详细信息"""
        sam = entry['sAMAccountName'].value
        dns = entry['dNSHostName'].value or '-'
        os_ = entry['operatingSystem'].value or 'Unknown'
        created = entry['whenCreated'].value or '-'

        print()
        print_info("RODC: %s (%s)" % (sam, dns))
        print_info("OS: %s" % os_)
        print_info("Created: %s" % created)
        print()

        # Managed By
        managed_dn = entry['msDS-ManagedBy'].value
        if managed_dn:
            managed_name = self._resolve_dn(managed_dn)
            print_success("Managed By: %s (%s)" % (managed_name or '?', managed_dn))
        else:
            print_info("Managed By: (none)")

        # krbtgt
        krbtgt_dn = self._get_first_value(entry, 'msDS-KrbTgtLink')
        if krbtgt_dn:
            krbtgt_name = self._resolve_dn(krbtgt_dn)
            print_success("krbtgt account: %s" % (krbtgt_name or krbtgt_dn))
        else:
            print_info("krbtgt account: (none)")

        # Password Replication Policy — Allowed
        print()
        allowed = self._get_all_values(entry, 'msDS-RevealOnDemandGroup')
        print_info("Password Replication Policy — Allowed (%d):" % len(allowed))
        if allowed:
            for dn in allowed:
                name = self._resolve_dn(dn)
                print_found("  %s%s" % ('' if name else '', name or dn))
        else:
            print_warn("  (empty)")

        # Password Replication Policy — Denied
        denied = self._get_all_values(entry, 'msDS-NeverRevealGroup')
        print_info("Password Replication Policy — Denied (%d):" % len(denied))
        if denied:
            for dn in denied:
                name = self._resolve_dn(dn)
                print_found("  %s" % (name or dn))
        else:
            print_warn("  (empty)")

        # Cached Passwords — msDS-RevealedList
        print()
        revealed = self._get_all_values(entry, 'msDS-RevealedList')
        if revealed:
            print_warn("Cached Passwords — %d account(s):" % len(revealed))
            rows = []
            for dn in revealed:
                name = self._resolve_dn(dn) or dn
                rows.append([name, dn])
            print()
            print_table(['Username', 'DN'], rows)
        else:
            print_success("No cached passwords (msDS-RevealedList is empty)")

        print()

    # ── RODC 辅助方法 ────────────────────────────────────────

    @staticmethod
    def _get_first_value(entry, attr):
        """安全获取多值属性的第一个值"""
        try:
            vals = entry[attr].values
            if vals:
                return vals[0]
        except (KeyError, IndexError, TypeError):
            pass
        return None

    @staticmethod
    def _get_all_values(entry, attr):
        """安全获取多值属性的所有值"""
        try:
            vals = entry[attr].values
            return list(vals) if vals else []
        except (KeyError, TypeError):
            return []

    def _resolve_dn(self, dn):
        """将 DN 反查为 sAMAccountName"""
        if not dn:
            return None
        try:
            self.client.search(
                self.domain_dumper.root,
                '(distinguishedName=%s)' % escape_filter_chars(dn),
                attributes=['sAMAccountName'],
            )
            if self.client.entries:
                return self.client.entries[0]['sAMAccountName'].value
        except Exception:
            pass
        return None

    # ── 内部辅助 ──────────────────────────────────────────────
    def _get_config_dn(self):
        """从 server info 获取 Configuration DN"""
        # RootDSE 属性在 server.info.other 里(不是 server.other)
        try:
            val = self.client.server.info.other.get('configurationNamingContext')
            if val:
                return val[0] if isinstance(val, list) else val
        except Exception:
            pass
        # 回退: 构造标准路径(注意: 子域 DC 的 config NC 在林根,不在本域)
        return 'CN=Configuration,%s' % self.domain_dumper.root
