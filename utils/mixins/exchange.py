#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exchange Mixin — Exchange 综合信息收集 (1 个命令)
"""

import re

from utils.ui import print_info, print_success, print_found, print_warn, print_header
from utils.helpers import resolve_host_ip

# ═══════════════════════════════════════════════════════════
#  Exchange 版本 → 名称 + 已知高危 CVE
#  注: 仅列出各版本已知公开 CVE，实际是否受影响取决于补丁状态
# ═══════════════════════════════════════════════════════════

EXCHANGE_VERSIONS = {
    '14.0': ('Exchange 2010 RTM', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
    ]),
    '14.1': ('Exchange 2010 SP1', [
        'CVE-2020-0688',
        'CVE-2021-26855 (ProxyLogon)',
    ]),
    '14.2': ('Exchange 2010 SP2', [
        'CVE-2020-0688',
        'CVE-2021-26855 (ProxyLogon)',
    ]),
    '14.3': ('Exchange 2010 SP3', [
        'CVE-2020-0688',
        'CVE-2021-26855 (ProxyLogon)',
    ]),
    '15.0': ('Exchange 2013', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
        'CVE-2021-26858 (ProxyLogon RCE)',
        'CVE-2021-27065 (ProxyLogon RCE)',
        'CVE-2021-34473 (ProxyShell Auth Bypass)',
    ]),
    '15.1': ('Exchange 2016', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
        'CVE-2021-26858 (ProxyLogon RCE)',
        'CVE-2021-27065 (ProxyLogon RCE)',
        'CVE-2021-34473 (ProxyShell Auth Bypass)',
        'CVE-2021-34523 (ProxyShell PrivEsc)',
        'CVE-2021-31207 (ProxyShell RCE)',
        'CVE-2022-41040 (ProxyNotShell SSRF)',
        'CVE-2022-41082 (ProxyNotShell RCE)',
        'CVE-2024-21410 (Privilege Escalation)',
    ]),
    '15.2': ('Exchange 2019', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
        'CVE-2021-26858 (ProxyLogon RCE)',
        'CVE-2021-27065 (ProxyLogon RCE)',
        'CVE-2021-34473 (ProxyShell Auth Bypass)',
        'CVE-2021-34523 (ProxyShell PrivEsc)',
        'CVE-2021-31207 (ProxyShell RCE)',
        'CVE-2022-41040 (ProxyNotShell SSRF)',
        'CVE-2022-41082 (ProxyNotShell RCE)',
        'CVE-2023-21709 (OWA EoP)',
        'CVE-2024-21410 (Privilege Escalation)',
    ]),
}

# 服务器角色位映射
# ─ Exchange 2010: 固定组合值 (ROLE_MAP 精确匹配, 仅多角色组合)
# ─ Exchange 2013+: 位掩码 (ROLE_BITS 按位 OR, 见 _parse_exchange_role)
# 注: 2010 与 2013+ 对位 16/64 的定义相反, 故 ROLE_MAP 只保留 2010 多角色
#    组合值, 单值交给位掩码解析以免冲突。
ROLE_MAP = {
    20: 'HubTransport',
    38: 'Mailbox+HT+CAS',
}

# Exchange 2013+ msExchCurrentServerRoles 位定义
ROLE_BITS = {
    2:     'Mailbox',
    4:     'ClientAccess',
    16:    'UnifiedMessaging',
    32:    'HubTransport',
    64:    'EdgeTransport',
    16384: 'FrontendTransport',
}


class ExchangeMixin:
    """Exchange 信息收集命令集"""

    # ── get_exchange ──────────────────────────────────────────
    def do_get_exchange(self, line):
        """get_exchange — Exchange 综合信息 (服务器/IP/版本/CVE/URL)"""
        print_info("Searching Exchange servers...")

        config_dn = self._get_config_dn()

        # ── 1. Exchange 服务器 (位于 Configuration 命名上下文) ──
        # msExchExchangeServer 对象只存在于配置分区:
        #   CN=<Server>,CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),
        #   CN=Administrative Groups,CN=<Org>,CN=Microsoft Exchange,CN=Services,<config>
        # 在域分区 (domain_dumper.root) 下搜索必然返回空。
        # 排除 msExchExchangeTransportServer — 真实服务器下挂在
        #   CN=Transport Configuration 下的 Mailbox/Frontend 传输子对象,
        # 它们继承了 msExchExchangeServer 类, 但不是独立服务器。
        self.client.search(
            config_dn,
            '(&(objectClass=msExchExchangeServer)'
            '(!(objectClass=msExchExchangeTransportServer)))',
            attributes=['cn', 'distinguishedName', 'msExchVersion',
                        'networkAddress', 'msExchCurrentServerRoles', 'serialNumber'],
        )
        entries = list(self.client.entries)

        if not entries:
            # 备用：通过 Exchange 邮箱存储 SPN 在域分区查找
            self.client.search(
                self.domain_dumper.root,
                '(servicePrincipalName=exchangeMDB*)',
                attributes=['sAMAccountName', 'dNSHostName', 'distinguishedName'],
            )
            entries = list(self.client.entries)

        if not entries:
            print_warn("No Exchange servers found")
            return

        print_success("Found %d Exchange server(s)" % len(entries))

        # ── 2. 逐服务器输出：IP / 版本 / CVE ─────────────────
        for entry in entries:
            # 名称
            name = None
            for attr in ('cn', 'sAMAccountName'):
                try:
                    name = entry[attr].value
                    if name:
                        break
                except (KeyError, Exception):
                    pass
            if not name:
                name = entry.entry_dn

            # IP
            ip = self._get_exchange_ip(entry, name)

            # 版本 (serialNumber 优先, 回退 msExchVersion 原始值)
            ver_name, ver_disp, ver_short = self._parse_exchange_version(entry)

            # 角色 (Exchange 2013+ 为位掩码)
            role = ''
            try:
                role = self._parse_exchange_role(entry['msExchCurrentServerRoles'].value)
            except (KeyError, Exception):
                pass

            # 输出
            print_header("Server: %s" % name)
            print_info("  IP:      %s" % ip)
            if role:
                print_info("  Role:    %s" % role)
            print_info("  Version: %s" % ver_name)
            if ver_disp:
                print_info("  Build:   %s" % ver_disp)

            cves = EXCHANGE_VERSIONS.get(ver_short, (None, []))[1]
            if cves:
                print_warn("  Known CVEs (if unpatched):")
                for cve in cves:
                    print_found("    %s" % cve)

        # ── 3. OWA / ECP 等虚拟目录 URL ──────────────────────
        self._print_exchange_urls()

    # ── 内部辅助 ──────────────────────────────────────────────

    def _parse_exchange_version(self, entry):
        """解析 Exchange 版本。

        msExchVersion 是 I8 整数 (编译期派生值, 非产品版本号, 无法可靠解码)。
        serialNumber 通常含可读串如 "Version 15.1 (Build 2507.6)"。

        返回 (version_name, build_display, version_short):
          version_short — 成功解析出已知版本时为 "15.1" 等, 否则空串
        """
        serial = ''
        try:
            v = entry['serialNumber'].value
            if v:
                serial = str(v)
        except (KeyError, Exception):
            pass

        msver_raw = ''
        try:
            v = entry['msExchVersion'].value
            if v is not None:
                msver_raw = str(v)
        except (KeyError, Exception):
            pass

        # 从 serialNumber 提取主.次版本号 (如 15.1)
        ver_short = ''
        if serial:
            m = re.search(r'(\d+\.\d+)', serial)
            if m:
                ver_short = m.group(1)

        if ver_short and ver_short in EXCHANGE_VERSIONS:
            return EXCHANGE_VERSIONS[ver_short][0], serial, ver_short

        build = serial or msver_raw
        if build:
            return 'Unknown (%s)' % (ver_short or build), build, ''

        return 'Unknown', '', ''

    def _parse_exchange_role(self, role_val):
        """解析 msExchCurrentServerRoles。

        Exchange 2010 用固定组合值 (ROLE_MAP 精确匹配);
        Exchange 2013+ 用位掩码 (ROLE_BITS 按位 OR), 单台多角色服务器
        会得到组合值 (如 Mailbox+ClientAccess+HubTransport+FrontendTransport)。
        末尾括号附原始值便于核对, 未识别位以 0xN? 标注 (如 legacy 残留位 0x1)。
        """
        try:
            val = int(role_val)
        except (TypeError, ValueError):
            return str(role_val) if role_val else ''
        if not val:
            return ''
        # Exchange 2010 固定组合精确匹配
        if val in ROLE_MAP:
            return ROLE_MAP[val]
        # Exchange 2013+ 位掩码解析
        names = []
        matched = 0
        for bit in sorted(ROLE_BITS):
            if val & bit:
                names.append(ROLE_BITS[bit])
                matched |= bit
        remaining = val & ~matched
        if remaining:
            names.append('0x%X?' % remaining)
        return '%s (%d)' % ('+'.join(names), val) if names else str(val)

    def _get_exchange_ip(self, entry, name):
        """解析 Exchange 服务器 IP。

        networkAddress 的 ncacn_ip_tcp 条目记录的是主机名 (NetBIOS/FQDN) 而非 IP,
        因此提取出主机名后还需 DNS 解析 (非域机器走 DC 直查回退)。
        """
        # 1. 从 networkAddress 提取主机名候选
        candidates = []
        try:
            for addr in entry['networkAddress'].values:
                s = str(addr)
                if not s.lower().startswith('ncacn_ip_tcp:'):
                    continue
                host = s.split(':', 1)[1].strip()
                # 个别格式带端口方括号: ncacn_ip_tcp:host[135]
                if '[' in host:
                    host = host.split('[')[0].strip()
                if host:
                    candidates.append(host)
        except (KeyError, Exception):
            pass

        # 服务器 cn/name 也是可解析候选
        if name:
            candidates.append(name)

        # 2. 逐个解析: 已是 IP / 系统 DNS / DC 直查 (resolve_host_ip 三级回退)
        for host in candidates:
            ip = resolve_host_ip(host, self.dc_address)
            if ip:
                return ip

        return '(unresolved)'

    def _print_exchange_urls(self):
        """查找 OWA / ECP / OAB 等虚拟目录 URL。

        不同 Exchange 版本 / 虚拟目录类型用不同属性存 URL
        (msExchInternalHostName / msExchInternalUrl 及 external 对应物等),
        故用 ['*'] 取全部属性再扫描值, 兼容各种命名, 且不会因请求
        不存在的属性名而抛 LDAPAttributeError。
        """
        config_dn = self._get_config_dn()
        if not config_dn:
            return

        print_header("Virtual Directories")
        try:
            self.client.search(
                config_dn,
                '(objectClass=msExchVirtualDirectory)',
                attributes=['*'],
            )
        except Exception:
            print_warn("  Unable to query virtual directories")
            return

        count = 0
        for entry in list(self.client.entries):
            cn = ''
            try:
                cn = entry['cn'].value or ''
            except (KeyError, Exception):
                pass
            # 只看前端站点 (Default Web Site), 后端 (Exchange Back End) 无对外 URL
            if 'Default Web Site' not in cn:
                continue

            # 扫描全部属性, 收集值以 http(s) 开头的 (internal/external URL/HostName)
            urls = []
            for attr in entry.entry_attributes:
                if attr in ('distinguishedName', 'objectCategory'):
                    continue
                try:
                    values = entry[attr].values
                except (KeyError, Exception):
                    continue
                for v in values:
                    sv = str(v)
                    if sv[:7].lower() == 'http://' or sv[:8].lower() == 'https://':
                        label = 'external' if 'external' in attr.lower() else 'internal'
                        urls.append((label, sv))

            if not urls:
                continue
            count += 1
            for label, url in urls:
                print_found("  %-9s %-42s %s" % (label, cn, url))

        if not count:
            print_warn("  No virtual directory URLs found")
