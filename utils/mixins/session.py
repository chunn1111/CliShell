#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Session Mixin — 会话枚举命令 (4 个)

通过 DCERPC over SMB 调用 Windows 远程管理接口:
  - computer_sessions: SRVSVC NetrSessionEnum (SMB 会话)
  - user_sessions:     WKSSVC NetrWkstaUserEnum (本地登录用户)
  - find_sessions:     全域搜索用户登录位置 (逐台 RPC)
  - active_users:      LDAP lastLogonTimestamp (近期活跃用户)
"""

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import srvs, wkst, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn, print_error
from utils.helpers import (
    parse_args, ad_timestamp_to_str,
    paged_search, print_table, resolve_host_ip,
)


class SessionMixin:
    """Session / 会话枚举命令集"""

    @staticmethod
    def _fmt_ts(ts):
        """统一时间戳格式化 (去除时区/微秒后缀, 1601 → Never)"""
        if not ts:
            return 'Never'
        s = ad_timestamp_to_str(ts)
        if '1601' in s:
            return 'Never'
        s = str(s)
        if '+' in s:
            s = s[:s.rfind('+')]
        if '.' in s:
            s = s[:s.rfind('.')]
        return s.strip()

    # ── RPC 连接辅助 ───────────────────────────────────────────

    def _rpc_connect(self, target, pipe):
        """
        建立 DCERPC over SMB 命名管道连接。

        先创建 SMBConnection 并完成认证 (与 assessment.py 相同模式)，
        再将已认证连接传给 SMBTransport 复用，避免管道路径兼容问题。

        Args:
            target: 目标主机 (IP 或主机名)
            pipe:   命名管道路径 (如 'srvsvc')

        Returns:
            (dce, rpc_transport, smb_connection) 三元组
        """
        from impacket.smbconnection import SMBConnection

        domain = self._extract_domain(self.base_DN)

        # 建立 SMB 连接并认证 (同 assessment.py find_gpp_passwords 模式)
        smb = SMBConnection(target, target)
        if self.nthash:
            smb.login(self.username, '', domain, self.lmhash, self.nthash)
        else:
            smb.login(self.username, self.password, domain)

        # 复用已认证的 SMB 连接建立 RPC 传输
        rpc = transport.SMBTransport(
            target, 445, pipe,
            smb_connection=smb,
        )
        rpc.connect()
        dce = rpc.get_dce_rpc()
        dce.connect()
        return dce, rpc, smb

    @staticmethod
    def _rpc_cleanup(dce, rpc, smb):
        """安全断开 RPC / SMB 连接"""
        try:
            dce.disconnect()
        except Exception:
            pass
        try:
            rpc.disconnect()
        except Exception:
            pass
        try:
            smb.close()
        except Exception:
            pass

    # ── computer_sessions ─────────────────────────────────────

    def do_computer_sessions(self, line):
        """
        computer_sessions <target> — 查看 SMB 会话 (谁连到目标的共享)

        通过 SRVSVC NetrSessionEnum (level 10) 枚举目标上的活跃 SMB 会话。
        target 可以是 IP 地址或主机名。
        """
        args = parse_args(line, 1, 1, "computer_sessions <target>  (e.g. computer_sessions 192.168.1.10)")
        if not args:
            return

        target = args[0]
        print_info("Enumerating SMB sessions on %s ..." % target)

        dce = rpc = smb = None
        try:
            dce, rpc, smb = self._rpc_connect(target, 'srvsvc')
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
            entries = resp['InfoStruct']['SessionInfo']['Level10']['Buffer']

            if not entries:
                print_success("No active SMB sessions on %s" % target)
                return

            rows = []
            for s in entries:
                cname = str(s['sesi10_cname'] or '').strip('\x00').strip()
                user = str(s['sesi10_username'] or '').strip('\x00').strip()
                active = int(s['sesi10_time'])
                idle = int(s['sesi10_idle_time'])

                # 跳过空用户和回环会话
                if not user:
                    continue
                if cname in ('\\127.0.0.1', '\\\\127.0.0.1',
                             '\\::1', '\\\\::1',
                             '\\0.0.0.0', '\\\\0.0.0.0'):
                    continue

                # 去掉 \\ 前缀
                if cname.startswith('\\\\'):
                    cname = cname[2:]
                elif cname.startswith('\\'):
                    cname = cname[1:]

                rows.append([cname, user, str(active), str(idle)])

            if not rows:
                print_success("No active SMB sessions on %s" % target)
                return

            print_found("Found %d SMB session(s) on %s" % (len(rows), target))
            print()
            print_table(['Client', 'Username', 'Active(s)', 'Idle(s)'], rows)

        except DCERPCException as e:
            print_error("RPC access denied: %s" % str(e))
        except Exception as e:
            print_error("Failed to connect to %s: %s" % (target, str(e)))
        finally:
            if dce:
                self._rpc_cleanup(dce, rpc, smb)

    # ── user_sessions ─────────────────────────────────────────

    def do_user_sessions(self, line):
        """
        user_sessions <target> — 查看目标上本地登录的用户

        通过 WKSSVC NetrWkstaUserEnum (level 1) 枚举目标上交互式登录的用户。
        target 可以是 IP 地址或主机名。
        """
        args = parse_args(line, 1, 1, "user_sessions <target>  (e.g. user_sessions 192.168.1.10)")
        if not args:
            return

        target = args[0]
        print_info("Enumerating logged-on users on %s ..." % target)

        dce = rpc = smb = None
        try:
            dce, rpc, smb = self._rpc_connect(target, 'wkssvc')
            dce.bind(wkst.MSRPC_UUID_WKST)

            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            entries = resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']

            if not entries:
                print_success("No logged-on users on %s" % target)
                return

            rows = []
            for u in entries:
                username = str(u['wkui1_username'] or '').strip('\x00').strip()
                domain = str(u['wkui1_logon_domain'] or '').strip('\x00').strip()
                logon_server = str(u['wkui1_logon_server'] or '').strip('\x00').strip()

                # 跳过机器账户和空用户
                if not username or username.endswith('$'):
                    continue

                rows.append([username, domain, logon_server])

            if not rows:
                print_success("No interactive user sessions on %s" % target)
                return

            print_found("Found %d logged-on user(s) on %s" % (len(rows), target))
            print()
            print_table(['Username', 'Domain', 'LogonServer'], rows)

        except DCERPCException as e:
            print_error("RPC access denied: %s" % str(e))
        except Exception as e:
            print_error("Failed to connect to %s: %s" % (target, str(e)))
        finally:
            if dce:
                self._rpc_cleanup(dce, rpc, smb)

    # ── find_sessions ─────────────────────────────────────────

    def do_find_sessions(self, line):
        """
        find_sessions <username> — 全域搜索用户在哪台机器登录

        通过 LDAP 枚举域内所有计算机，逐台 RPC 调用 WKSSVC
        NetrWkstaUserEnum 查找目标用户的登录会话。
        """
        args = parse_args(line, 1, 2, "find_sessions <username> [limit]  (e.g. find_sessions administrator [5])")
        if not args:
            return

        target_user = args[0].lower()
        max_hosts = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0  # 0=不限制

        # 验证用户是否存在
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=%s))' % escape_filter_chars(args[0]),
            attributes=['sAMAccountName'],
        )
        if not self.client.entries:
            print_error("User '%s' not found in domain" % args[0])
            return

        # LDAP 枚举所有启用的计算机
        print_info("Enumerating computers from LDAP...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=computer)',
            attributes=['sAMAccountName', 'dNSHostName', 'userAccountControl'],
        )

        # 过滤禁用的机器，收集 (name, ip) 列表
        computers = []
        for entry in entries:
            uac = entry['userAccountControl'].value or 0
            if isinstance(uac, str):
                uac = int(uac, 16) if uac.startswith('0x') else int(uac)
            if uac & 0x0002:  # ACCOUNTDISABLE
                continue
            sam = entry['sAMAccountName'].value
            dns = entry['dNSHostName'].value or ''
            computers.append((sam, dns))

        total = len(computers)
        if max_hosts and total > max_hosts:
            computers = computers[:max_hosts]
            total = len(computers)
            print_info("Limit enabled: only scanning first %d computer(s)" % total)
        print_info("Searching for '%s' across %d computer(s)..." % (target_user, total))
        print()

        # 逐台查询
        found = []
        for idx, (sam, dns) in enumerate(computers, 1):
            # 解析 IP (系统 DNS → DC 直查回退, 非域机器也能解析)
            if not dns:
                print_error("  [%d/%d] %s — skipped (no dNSHostName)" % (idx, total, sam))
                continue
            ip = resolve_host_ip(dns, self.dc_address)
            if not ip:
                print_error("  [%d/%d] %s — skipped (unresolved: %s)" % (idx, total, sam, dns))
                continue

            print_info("[%d/%d] %s (%s)..." % (idx, total, sam, ip))

            dce = rpc = smb = None
            try:
                dce, rpc, smb = self._rpc_connect(ip, 'wkssvc')
                dce.bind(wkst.MSRPC_UUID_WKST)

                resp = wkst.hNetrWkstaUserEnum(dce, 1)
                user_entries = resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']

                if user_entries:
                    for u in user_entries:
                        uname = str(u['wkui1_username'] or '').strip('\x00').strip()
                        if uname.lower() == target_user:
                            domain = str(u['wkui1_logon_domain'] or '').strip('\x00').strip()
                            logon_server = str(u['wkui1_logon_server'] or '').strip('\x00').strip()
                            print_success("  -> Found! (%s\\%s @ %s)" % (domain, uname, logon_server))
                            found.append([sam, ip, domain, logon_server])

            except Exception as e:
                print_error("  -> %s: %s" % (sam, str(e)[:80]))
            finally:
                if dce:
                    self._rpc_cleanup(dce, rpc, smb)

        # 汇总输出
        print()
        if found:
            print_found("Found '%s' on %d host(s)" % (target_user, len(found)))
            print()
            print_table(['Computer', 'IP', 'Domain', 'LogonServer'], found)
        else:
            print_warn("User '%s' not found on any host" % target_user)

    # ── active_users ──────────────────────────────────────────

    def do_active_users(self, line):
        """active_users — 近期活跃用户 (基于 lastLogonTimestamp)"""
        import datetime

        now = datetime.datetime.utcnow()
        threshold_days = 30
        threshold = now - datetime.timedelta(days=threshold_days)
        epoch = datetime.datetime(1601, 1, 1)
        threshold_ts = int((threshold - epoch).total_seconds() * 10000000)

        print_info("Finding users active in last %d days..." % threshold_days)
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(lastLogonTimestamp>=%d))' % threshold_ts,
            attributes=['sAMAccountName', 'lastLogon', 'lastLogonTimestamp', 'logonCount'],
        )

        if not entries:
            print_warn("No active users found")
            return

        rows = []
        for entry in entries:
            sam = entry['sAMAccountName'].value
            last = entry['lastLogonTimestamp'].value or 0
            count = str(entry['logonCount'].value or 0)
            rows.append([sam, count, self._fmt_ts(last)])

        print()
        print_table(['Username', 'Logons', 'lastLogonTs'], rows)
