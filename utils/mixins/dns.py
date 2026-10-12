#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Info Mixin — DNS 相关命令 (4 个)

DNS 记录提取采用分层策略:
  1. dns_records: adidnsdump 风格 — 直接解析 dnsRecord 二进制属性 (MS-DNSP)
  2. dns_hosts:   ldapdomaindump 风格 — 通过 computer 对象 dNSHostName 获取 IP (保底)
  3. dns_zones:   枚举 Domain/Forest/Legacy 三条路径的 DNS 区域
  4. dns_servers: 查找 DNS 服务器
"""

import socket
import datetime
from struct import unpack

from impacket.structure import Structure

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import parse_args, paged_search, resolve_host_ip


# ═══════════════════════════════════════════════════════════
#  MS-DNSP 二进制结构定义 (参考 adidnsdump / [MS-DNSP])
# ═══════════════════════════════════════════════════════════

RECORD_TYPE = {
    0: 'ZERO', 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
    12: 'PTR', 15: 'MX', 28: 'AAAA', 33: 'SRV',
}


class DNS_RECORD(Structure):
    """dnsRecord — [MS-DNSP] section 2.3.2.2"""
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':'),
    )


class DNS_COUNT_NAME(Structure):
    """DNS_COUNT_NAME — [MS-DNSP] section 2.2.2.2.2"""
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':'),
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for _ in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind + 1])[0]
            labels.append(self['RawName'][ind + 1:ind + 1 + nextlen].decode('utf-8'))
            ind += nextlen + 1
        labels.append('')
        return '.'.join(labels)


class DNS_RPC_RECORD_A(Structure):
    """A record — [MS-DNSP] section 2.2.2.2.4.1"""
    structure = (('address', ':'),)

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])


class DNS_RPC_RECORD_AAAA(Structure):
    """AAAA record — [MS-DNSP] section 2.2.2.2.4.17"""
    structure = (('ipv6Address', '16s'),)

    def formatCanonical(self):
        return socket.inet_ntop(socket.AF_INET6, self['ipv6Address'])


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """NS/CNAME/PTR — [MS-DNSP] section 2.2.2.2.4.2"""
    structure = (('nameNode', ':', DNS_COUNT_NAME),)


class DNS_RPC_RECORD_SOA(Structure):
    """SOA record — [MS-DNSP] section 2.2.2.2.4.3"""
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_SRV(Structure):
    """SRV record — [MS-DNSP] section 2.2.2.2.4.18"""
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_TS(Structure):
    """Tombstone timestamp — [MS-DNSP] section 2.2.2.2.4.23"""
    structure = (('entombedTime', '<Q'),)


def _parse_dns_value(data):
    """解析单条 dnsRecord 二进制数据 → (type_name, value_str)"""
    dr = DNS_RECORD(data)
    rtype = RECORD_TYPE.get(dr['Type'], '?%d' % dr['Type'])

    # Tombstone
    if dr['Type'] == 0:
        ts = DNS_RPC_RECORD_TS(dr['Data'])
        us = int(ts['entombedTime'] / 10)
        try:
            dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
            return rtype, 'Tombstoned %s' % dt.strftime('%Y-%m-%d')
        except OverflowError:
            return rtype, 'Tombstoned'

    # A
    if dr['Type'] == 1:
        return rtype, DNS_RPC_RECORD_A(dr['Data']).formatCanonical()

    # AAAA
    if dr['Type'] == 28:
        return rtype, DNS_RPC_RECORD_AAAA(dr['Data']).formatCanonical()

    # NS / CNAME / PTR
    if dr['Type'] in (2, 5, 12):
        rec = DNS_RPC_RECORD_NODE_NAME(dr['Data'])
        return rtype, rec['nameNode'].toFqdn()

    # SRV
    if dr['Type'] == 33:
        rec = DNS_RPC_RECORD_SRV(dr['Data'])
        return rtype, '%s:%d (pri=%d wt=%d)' % (
            rec['nameTarget'].toFqdn(), rec['wPort'],
            rec['wPriority'], rec['wWeight'])

    # SOA
    if dr['Type'] == 6:
        rec = DNS_RPC_RECORD_SOA(dr['Data'])
        return rtype, 'primary=%s serial=%d refresh=%d' % (
            rec['namePrimaryServer'].toFqdn(),
            rec['dwSerialNo'], rec['dwRefresh'])

    return rtype, '(%d bytes)' % len(dr['Data'])


# ═══════════════════════════════════════════════════════════
#  DNS Mixin
# ═══════════════════════════════════════════════════════════

class DNSMixin:
    """DNS Info 命令集"""

    # ── dns_zones ─────────────────────────────────────────────
    def do_dns_zones(self, line):
        """dns_zones — DNS 区域列表 (含域/林/旧版路径)"""
        print_info("Searching DNS zones...")
        all_zones = []
        paths = [
            ('Domain', 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.domain_dumper.root),
            ('Forest',  'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % self.domain_dumper.root),
            ('Legacy',  'CN=MicrosoftDNS,CN=System,%s' % self.domain_dumper.root),
        ]
        for label, dns_dn in paths:
            try:
                self.client.search(
                    dns_dn, '(objectClass=dnsZone)',
                    search_scope='LEVEL', attributes=['dc'],
                )
                for entry in self.client.entries:
                    zone = entry['dc'].value
                    all_zones.append(zone)
                    print_found("[%s] %s" % (label, zone))
            except Exception:
                pass

        if not all_zones:
            print_warn("No DNS zones found")
        else:
            print_success("Found %d zone(s)" % len(all_zones))

    # ── dns_records ───────────────────────────────────────────
    def do_dns_records(self, line):
        """dns_records <zone> — 解析 DNS 记录 (adidnsdump 风格，MS-DNSP 二进制解析)"""
        args = parse_args(line, 1, 1, "dns_records corp.local")
        zone = args[0]

        # 按优先级尝试三个路径
        paths = [
            'DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones,%s' % (zone, self.domain_dumper.root),
            'DC=%s,CN=MicrosoftDNS,DC=ForestDnsZones,%s' % (zone, self.domain_dumper.root),
            'DC=%s,CN=MicrosoftDNS,CN=System,%s' % (zone, self.domain_dumper.root),
        ]

        entries = []
        for dns_dn in paths:
            try:
                entries = paged_search(
                    self.client, dns_dn,
                    '(objectClass=dnsNode)',
                    attributes=['name', 'dnsRecord', 'dNSTombstoned'],
                    search_scope='LEVEL',
                )
                if entries:
                    break
            except Exception:
                continue

        if not entries:
            print_warn("No DNS records found for zone: %s" % zone)
            print_info("Try: dns_hosts (fallback via computer objects)")
            return

        # 收集记录行
        rows = []
        for entry in entries:
            record_name = entry['name'].value
            if not record_name:
                dn_parts = entry.entry_dn.split(',')
                if dn_parts:
                    rdn = dn_parts[0]
                    record_name = rdn.split('=', 1)[1] if '=' in rdn else rdn
            if record_name is None:
                record_name = '?'

            try:
                if entry['dNSTombstoned'].value:
                    continue
            except (KeyError, Exception):
                pass

            try:
                raw_records = entry['dnsRecord'].raw_values
                for raw in raw_records:
                    try:
                        rtype, value = _parse_dns_value(raw)
                        if rtype == 'ZERO':
                            continue
                        display = record_name if record_name != '@' else zone
                        rows.append([display, rtype, value])
                    except Exception:
                        rows.append([record_name, '?', '(parse error)'])
            except (KeyError, TypeError):
                rows.append([record_name, '?', '(no data)'])

        if not rows:
            print_warn("No parseable records found")
            return

        print_success("Found %d record(s) in zone %s" % (len(rows), zone))

        header = ['Name', 'Type', 'Value']
        col_lens = [
            max(len(header[0]), max(len(r[0]) for r in rows)),
            max(len(header[1]), max(len(r[1]) for r in rows)),
            max(len(header[2]), max(len(r[2]) for r in rows)),
        ]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        for r in rows:
            print(fmt.format(*r))

    # ── dns_hosts ─────────────────────────────────────────────
    def do_dns_hosts(self, line):
        """dns_hosts — 通过计算机对象获取主机 IP"""
        print_info("Enumerating host IPs via computer objects...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=computer)(dNSHostName=*))',
            attributes=['sAMAccountName', 'dNSHostName', 'operatingSystem'],
        )

        if not entries:
            print_warn("No computers with dNSHostName found")
            return

        rows = []
        for entry in entries:
            try:
                hostname = entry['dNSHostName'].value or ''
            except (KeyError, TypeError):
                hostname = ''
            try:
                os_name = entry['operatingSystem'].value or ''
            except (KeyError, TypeError):
                os_name = ''
            if not hostname:
                continue
            ip = self._dns_resolve(hostname) or '(unresolved)'
            rows.append([hostname, ip, os_name])

        if not rows:
            print_warn("No resolvable hosts found")
            return

        header = ['Hostname', 'IP', 'OS']
        col_lens = [
            max(len(header[0]), max(len(r[0]) for r in rows)),
            max(len(header[1]), max(len(r[1]) for r in rows)),
            max(len(header[2]), max(len(r[2]) for r in rows)),
        ]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print_success("Found %d host(s)" % len(rows))
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        for r in rows:
            print(fmt.format(*r))

    def _dns_resolve(self, hostname):
        """尝试解析主机名为 IP (LDAP DNS A 记录缓存 → 系统 DNS → DC 直查)"""
        # 惰性构建 DNS A 记录缓存 {hostname → IP}
        if not hasattr(self, '_dns_a_cache'):
            self._dns_a_cache = self._build_dns_a_cache()
        if hostname in self._dns_a_cache:
            return self._dns_a_cache[hostname]
        # 回退: resolve_host_ip (系统 DNS → DC 直查, 非域机器兜底)
        return resolve_host_ip(hostname, self.dc_address)

    def _build_dns_a_cache(self):
        """从 LDAP DNS 区域构建 {hostname → IP} 映射"""
        cache = {}
        dns_paths = [
            'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.domain_dumper.root,
            'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % self.domain_dumper.root,
            'CN=MicrosoftDNS,CN=System,%s' % self.domain_dumper.root,
        ]
        for dns_base in dns_paths:
            try:
                self.client.search(
                    dns_base, '(objectClass=dnsZone)',
                    search_scope='LEVEL', attributes=['dc'],
                )
            except Exception:
                continue
            zones = [e['dc'].value for e in self.client.entries if e['dc'] and e['dc'].value]
            for zone in zones:
                zone_dn = 'DC=%s,%s' % (zone, dns_base)
                try:
                    entries = paged_search(
                        self.client, zone_dn,
                        '(objectClass=dnsNode)',
                        attributes=['name', 'dnsRecord'],
                        search_scope='LEVEL',
                    )
                except Exception:
                    continue
                for entry in entries:
                    try:
                        record_name = entry['name'].value or '@'
                    except (KeyError, TypeError):
                        continue
                    if record_name == '@':
                        record_name = zone
                    # 构造 FQDN
                    fqdn = '%s.%s' % (record_name, zone) if not record_name.endswith(zone) else record_name
                    try:
                        raw_records = entry['dnsRecord'].raw_values
                    except (KeyError, TypeError):
                        continue
                    for raw in raw_records:
                        try:
                            dr = DNS_RECORD(raw)
                            if dr['Type'] == 1:  # A 记录
                                _, value = _parse_dns_value(raw)
                                if value:
                                    cache[fqdn.lower()] = value
                                    break
                        except Exception:
                            continue
        return cache

    # ── dns_servers ───────────────────────────────────────────
    def do_dns_servers(self, line):
        """dns_servers — DNS 服务器"""
        print_info("Searching DNS servers...")

        # 方法 1: 通过 SPN 查找
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=computer)(servicePrincipalName=DNS*))',
            attributes=['sAMAccountName', 'dNSHostName'],
        )
        if self.client.entries:
            print_success("Found %d DNS server(s)" % len(self.client.entries))
            for entry in self.client.entries:
                print_found(entry['dNSHostName'].value or entry['sAMAccountName'].value)
            return

        # 方法 2: DC 通常也是 DNS 服务器 (保底)
        print_warn("No DNS SPN found, falling back to DCs...")
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=['sAMAccountName', 'dNSHostName'],
        )
        if self.client.entries:
            for entry in self.client.entries:
                print_found(entry['dNSHostName'].value or entry['sAMAccountName'].value)
        else:
            print_warn("No DNS servers or DCs found")
