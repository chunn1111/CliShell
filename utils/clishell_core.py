#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CliShell — Interactive LDAP shell for Active Directory penetration testing.

Based on impacket's ntlmrelayx LDAP shell, redesigned with:
  - Sliver C2 style UI (random banners, ability taglines, colored prefixes)
  - Modular mixin architecture (15+ command categories, 120+ commands)
  - Robust error handling and readable code

Author:  CliShell Contributors
License: Apache 2.0 (see LICENSE)
"""

import re
import cmd

from colorama import Fore, Style

# UI 组件
from utils.ui import print_banner, print_help, print_info, print_error, print_success, print_found, print_warn

# Mixin 命令模块 — 按功能分类，每个 Mixin 独立一个文件
from utils.mixins.computer import ComputerMixin
from utils.mixins.user import UserMixin
from utils.mixins.group import GroupMixin
from utils.mixins.ou import OUMixin
from utils.mixins.domain_info import DomainInfoMixin
from utils.mixins.dns import DNSMixin
from utils.mixins.exchange import ExchangeMixin
from utils.mixins.delegation import DelegationMixin
from utils.mixins.acl import ACLMixin
from utils.mixins.session import SessionMixin
from utils.mixins.privilege import PrivilegeMixin
from utils.mixins.gpo import GPOMixin
from utils.mixins.adcs import AdcsMixin
from utils.mixins.search import SearchMixin
from utils.mixins.assessment import AssessmentMixin
from utils.mixins.connection import ConnectionMixin
from utils.mixins.basic_info import BasicInfoMixin

from ldap3.utils.conv import escape_filter_chars
from impacket import LOG


# ═══════════════════════════════════════════════════════════════
#  Readline 兼容 prompt
#
#  ANSI 转义序列 (\033[...m) 被 readline 算作可见字符，
#  导致 Tab 补全时光标定位偏移、补全文本覆盖到 prompt 前面。
#  解决方案: 用 \001 (RL_PROMPT_START_IGNORE) 和 \002
#  (RL_PROMPT_END_IGNORE) 包裹不可见序列，让 readline
#  只计算实际显示字符的宽度。
# ═══════════════════════════════════════════════════════════════

_ANSI_RE = re.compile(r'(\033\[[0-9;]*m)')


def _rl_safe_prompt(text):
    """包裹 ANSI 转义序列，让 readline 正确计算 prompt 可见宽度"""
    return _ANSI_RE.sub(r'\001\1\002', text)


# ═══════════════════════════════════════════════════════════════
#  CliShell — 主交互 Shell 类
#
#  继承顺序 (MRO):
#    所有 Mixin → cmd.Cmd
#  每个 Mixin 提供 do_* 命令方法，通过 self.client / self.domain_dumper
#  访问共享的 LDAP 连接和域信息。
# ═══════════════════════════════════════════════════════════════

class CliShell(
    BasicInfoMixin,
    ComputerMixin,
    UserMixin,
    GroupMixin,
    OUMixin,
    DomainInfoMixin,
    DNSMixin,
    ExchangeMixin,
    DelegationMixin,
    ACLMixin,
    SessionMixin,
    PrivilegeMixin,
    GPOMixin,
    AdcsMixin,
    SearchMixin,
    AssessmentMixin,
    ConnectionMixin,
    cmd.Cmd,
):
    """
    Interactive LDAP shell for AD penetration testing.

    通过多继承组合 15+ 个功能模块，提供 120+ 条命令。
    共享状态:
      - self.client        — ldap3.Connection (LDAP/LDAPS 连接)
      - self.domain_dumper — ldapdomaindump.domainDumper (域信息)
      - self.base_DN       — 基础 DN (如 DC=corp,DC=local)
      - self.username      — 当前认证用户
      - self.dc_address    — DC 的 IP 地址
    """

    def __init__(self, base_DN, domain_dumper, client,
                 username='unknown', dc_address='0.0.0.0',
                 password='', lmhash='', nthash=''):
        cmd.Cmd.__init__(self)
        self.base_DN = base_DN
        self.use_rawinput = True

        # 共享 LDAP 连接和域信息
        self.client = client
        self.domain_dumper = domain_dumper
        self.username = username
        self.dc_address = dc_address

        # 认证凭据 (GPP 密码提取需要 SMB 连接)
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash

        # ── Prompt: CliShell (user@ip)> ──────────────────────────
        # \001/\002 包裹 ANSI 序列，让 readline 不计入可见宽度
        # 不用 \n 前缀 — 由 postcmd 提供空行间距
        self.prompt = _rl_safe_prompt(
            Fore.WHITE + Style.BRIGHT + 'CliShell '
            + Fore.WHITE + Style.BRIGHT + '('
            + Fore.WHITE + Style.BRIGHT + self.username
            + Fore.WHITE + Style.BRIGHT + '@'
            + Fore.WHITE + Style.BRIGHT + self.dc_address
            + Fore.WHITE + Style.BRIGHT + ')'
            + Fore.RED + Style.BRIGHT + '> '
            + Style.RESET_ALL
        )


    # ═══════════════════════════════════════════════════════════
    #  面板辅助方法 — get_basic_info 命令使用
    # ═══════════════════════════════════════════════════════════

    def _get_user_acl_summary(self):
        """
        获取当前用户对自身的 ACL 权限概要。
        读取用户对象的 nTSecurityDescriptor 并解析关键权限。
        """
        from ldap3.protocol.microsoft import security_descriptor_control
        from impacket.ldap import ldaptypes

        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(
            self.domain_dumper.root,
            '(sAMAccountName=%s)' % escape_filter_chars(self.username),
            attributes=['nTSecurityDescriptor', 'objectSid'],
            controls=controls,
        )
        if not self.client.entries:
            return []

        try:
            entry = self.client.entries[0]
            sd_data = entry['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
            user_sid = str(entry['objectSid'].value)
        except (IndexError, KeyError, Exception):
            return []

        # 权限映射
        # [Bugfix] GenericWrite 映射形态是 0x00020028 (RC|SELF|WRITE_PROP),
        # 0x00020094 是 GENERIC_READ (只读), 不能当写权限
        priv_map = {
            0x000f01ff: 'GenericAll',
            0x00040000: 'WriteDacl',
            0x00080000: 'WriteOwner',
            0x00020028: 'GenericWrite',
            0x00000001: 'ReadData',
        }

        found_privs = set()
        for ace in sd['Dacl'].aces:
            try:
                ace_sid = ace['Ace']['Sid'].formatCanonical()
                mask = ace['Ace']['Mask']['Mask']

                # 只关注当前用户的 ACE 或 Everyone/Self
                if ace_sid != user_sid and ace_sid not in ('S-1-1-0', 'S-1-5-10', 'S-1-5-11', 'S-1-5-32-545'):
                    continue

                # 检查高权限
                if mask & 0x000f01ff == 0x000f01ff:
                    found_privs.add('GenericAll')
                if mask & 0x00040000:
                    found_privs.add('WriteDacl')
                if mask & 0x00080000:
                    found_privs.add('WriteOwner')
                if mask & 0x00020028 == 0x00020028:
                    found_privs.add('GenericWrite')
                if mask & 0x00000100:
                    found_privs.add('Delete')
            except Exception:
                continue

        return sorted(found_privs)

    # ── 基础 cmd.Cmd 覆写 ────────────────────────────────────

    def emptyline(self):
        """空行不重复执行上一条命令"""
        pass

    def postcmd(self, stop, line):
        """每条命令执行后输出空行，替代 prompt 中的 \n"""
        if not stop:
            print()
        return stop

    def onecmd(self, s):
        """执行单条命令，统一异常处理"""
        try:
            return cmd.Cmd.onecmd(self, s)
        except Exception as e:
            print_error(str(e))
            LOG.error(e)
            LOG.debug('Exception info', exc_info=True)

    def completenames(self, text, *ignored):
        """Tab 补全命令名"""
        return [name[3:] for name in self.get_names()
                if name.startswith('do_' + text)]

    def do_help(self, line):
        """help — 显示帮助信息"""
        print_help()

    def do_exit(self, line):
        """exit — 退出 shell"""
        return True

    def do_EOF(self, line):
        """Ctrl+D 退出"""
        print(Fore.YELLOW + Style.BRIGHT + 'Bye!')
        return True

    # ── 内部辅助 ──────────────────────────────────────────────

    def _resolve_sid(self, sid):
        """
        将 SID 反查为 sAMAccountName。
        返回字符串 (如 'Domain Admins') 或 None。
        """
        try:
            self.client.search(
                self.domain_dumper.root,
                '(objectSid=%s)' % escape_filter_chars(str(sid)),
                attributes=['sAMAccountName'],
            )
            if self.client.entries:
                return self.client.entries[0]['sAMAccountName'].value
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_domain(base_dn):
        """从 base DN 提取域名 (DC=corp,DC=local → corp.local)"""
        dc_part = base_dn[base_dn.upper().find('DC='):]
        domain = re.sub(',DC=', '.', dc_part, flags=re.I)
        return domain[3:]  # 去掉开头的 "DC=" 转换后的 "."
