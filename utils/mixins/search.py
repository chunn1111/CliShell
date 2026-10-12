#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Search Mixin — 通用搜索命令 (6 个, 含原有 search)
"""

import shlex
from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import parse_args, display_entries, paged_search, print_table_capped


class SearchMixin:
    """Search 命令集"""

    # ── search (原有通用搜索) ─────────────────────────────────
    def do_search(self, line):
        """search <query> [attr1,attr2,...] — 通用搜索"""
        arguments = shlex.split(line) if line.strip() else []
        if not arguments:
            raise Exception("A query is required.")

        filter_attributes = ['name', 'distinguishedName', 'sAMAccountName']
        attributes = filter_attributes[:] + ['objectSid']
        for argument in arguments[1:]:
            attributes.append(argument)

        # 构造 OR 搜索过滤器
        search_query = "".join(
            "(%s=*%s*)" % (attr, escape_filter_chars(arguments[0]))
            for attr in filter_attributes
        )
        self._display_search('(|%s)' % search_query, attributes)

    # ── search_user ───────────────────────────────────────────
    def do_search_user(self, line):
        """search_user <keyword> — 搜索用户"""
        args = parse_args(line, 1, 1, "search_user admin")
        filt = '(&(objectClass=user)(|(sAMAccountName=*%s*)(displayName=*%s*)(cn=*%s*)))' % (
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
        )
        entries = paged_search(
            self.client, self.domain_dumper.root, filt,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'userAccountControl'],
        )
        self._print_results(entries, ['sAMAccountName', 'displayName'])

    # ── search_group ──────────────────────────────────────────
    def do_search_group(self, line):
        """search_group <keyword> — 搜索组"""
        args = parse_args(line, 1, 1, "search_group admin")
        filt = '(&(objectClass=group)(|(sAMAccountName=*%s*)(displayName=*%s*)(cn=*%s*)))' % (
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
        )
        entries = paged_search(
            self.client, self.domain_dumper.root, filt,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'description'],
        )
        self._print_results(entries, ['sAMAccountName', 'description'])

    # ── search_computer ───────────────────────────────────────
    def do_search_computer(self, line):
        """search_computer <keyword> — 搜索机器"""
        args = parse_args(line, 1, 1, "search_computer DC")
        filt = '(&(objectClass=computer)(|(sAMAccountName=*%s*)(dNSHostName=*%s*)(cn=*%s*)))' % (
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
        )
        entries = paged_search(
            self.client, self.domain_dumper.root, filt,
            attributes=['sAMAccountName', 'dNSHostName', 'operatingSystem', 'distinguishedName'],
        )
        self._print_results(entries, ['sAMAccountName', 'dNSHostName', 'operatingSystem'])

    # ── search_ou ─────────────────────────────────────────────
    def do_search_ou(self, line):
        """search_ou <keyword> — 搜索 OU"""
        args = parse_args(line, 1, 1, "search_ou servers")
        filt = '(&(objectClass=organizationalUnit)(|(name=*%s*)(description=*%s*)(ou=*%s*)))' % (
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
            escape_filter_chars(args[0]),
        )
        entries = paged_search(
            self.client, self.domain_dumper.root, filt,
            attributes=['name', 'distinguishedName', 'description'],
        )
        print_success("Found %d result(s)" % len(entries))
        rows = [[e['name'].value or '-',
                 e['description'].value or '-',
                 e.entry_dn] for e in entries]
        print_table_capped(['Name', 'Description', 'DN'], rows, tag='search_ou')

    # ── search_spn ────────────────────────────────────────────
    def do_search_spn(self, line):
        """search_spn <keyword> — 搜索 SPN"""
        args = parse_args(line, 1, 1, "search_spn HTTP")
        filt = '(&(servicePrincipalName=*%s*)(objectClass=user))' % escape_filter_chars(args[0])
        entries = paged_search(
            self.client, self.domain_dumper.root, filt,
            attributes=['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
        )
        print_success("Found %d result(s)" % len(entries))
        for entry in entries:
            spns = entry['servicePrincipalName'].values
            for spn in spns:
                if args[0].lower() in spn.lower():
                    print_found("%s — %s" % (entry['sAMAccountName'].value, spn))

    # ── 内部辅助 ──────────────────────────────────────────────
    def _display_search(self, query, attributes):
        """执行搜索并显示结果 (原有 search 逻辑，带分页)"""
        entries = paged_search(self.client, self.domain_dumper.root, query, attributes=attributes)
        for entry in entries:
            print_found(entry.entry_dn)
            for attr in attributes:
                value = entry[attr].value if attr in entry.entry_attributes else None
                if value:
                    from utils.ui import Fore, Style
                    print("  %s%s%s: %s" % (Fore.CYAN, attr, Style.RESET_ALL, value))
            from utils.ui import Fore
            print(Fore.LIGHTBLACK_EX + "─" * 40)

    @staticmethod
    def _print_results(entries, attrs):
        """通用结果打印"""
        from utils.ui import Fore, Style

        if not entries:
            print_warn("No results found")
            return

        print_success("Found %d result(s)" % len(entries))
        for entry in entries:
            print_found(entry.entry_dn)
            for attr in attrs:
                try:
                    val = entry[attr].value
                    if val:
                        print("  %s%s%s: %s" % (Fore.CYAN, attr, Style.RESET_ALL, val))
                except (KeyError, Exception):
                    pass
            print(Fore.LIGHTBLACK_EX + "─" * 50)
