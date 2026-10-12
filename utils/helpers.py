#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared LDAP helper utilities for CliShell mixins.
所有 mixin 共用的底层 LDAP 工具函数。
"""

import re
import os
import csv
import socket
import struct
import ipaddress
import datetime
import shlex
import ldap3
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.utils.conv import escape_filter_chars
from impacket import LOG
from impacket.ldap import ldaptypes

from utils.ui import print_info, print_success, print_error, print_found, print_warn

# ═══════════════════════════════════════════════════════════════
#  常量
# ═══════════════════════════════════════════════════════════════

# AD 用户账户控制标志位
UAC = {
    'SCRIPT':                          0x0001,
    'ACCOUNTDISABLE':                  0x0002,
    'HOMEDIR_REQUIRED':                0x0008,
    'LOCKOUT':                         0x0010,
    'PASSWD_NOTREQD':                  0x0020,
    'PASSWD_CANT_CHANGE':              0x0040,
    'ENCRYPTED_TEXT_PWD_ALLOWED':      0x0080,
    'TEMP_DUPLICATE_ACCOUNT':          0x0100,
    'NORMAL_ACCOUNT':                  0x0200,
    'INTERDOMAIN_TRUST_ACCOUNT':       0x0800,
    'WORKSTATION_TRUST_ACCOUNT':       0x1000,
    'SERVER_TRUST_ACCOUNT':            0x2000,
    'DONT_EXPIRE_PASSWORD':            0x10000,
    'MNS_LOGON_ACCOUNT':               0x20000,
    'SMARTCARD_REQUIRED':              0x40000,
    'TRUSTED_FOR_DELEGATION':          0x80000,
    'NOT_DELEGATED':                   0x100000,
    'USE_DES_KEY_ONLY':                0x200000,
    'DONT_REQ_PREAUTH':                0x400000,
    'PASSWORD_EXPIRED':                0x800000,
    'TRUSTED_TO_AUTH_FOR_DELEGATION':  0x1000000,
    'NO_AUTH_DATA_REQUIRED':           0x2000000,
}

# AD 信任方向
TRUST_DIRECTION = {0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional'}

# AD 信任类型
TRUST_TYPE = {1: 'Downlevel (Windows NT)', 2: 'Uplevel (Active Directory)', 3: 'MIT Kerberos'}

# LDAP 匹配规则: 链式匹配 (递归查组嵌套)
LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

# AD epoch: 1601-01-01 00:00:00 (100ns 精度)
_AD_EPOCH = datetime.datetime(1601, 1, 1)


# ═══════════════════════════════════════════════════════════════
#  时间戳工具
# ═══════════════════════════════════════════════════════════════

def ad_timestamp_to_str(ts):
    """
    将 AD 时间戳转为可读字符串 (本地时区)。
    AD 存储的时间是 UTC, 直接显示会与本地时间有时差误读 (如 UTC+8 差 8 小时),
    统一 astimezone() 转为本机时区。
    ldap3 可能返回以下类型:
      - int (原始 100ns 时间戳)
      - datetime.datetime (ldap3 自动转换, 通常带 UTC tzinfo)
      - str / bytes
      - None / 0
    """
    if ts is None or ts == 0:
        return "Never"
    if isinstance(ts, datetime.datetime):
        dt = ts
    else:
        try:
            dt = _AD_EPOCH + datetime.timedelta(microseconds=int(ts) / 10)
        except (OverflowError, ValueError, OSError, TypeError):
            return "Invalid"
    # UTC → 本地时区
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        dt = dt.astimezone()
    except Exception:
        pass
    return dt.strftime("%Y-%m-%d %H:%M:%S")



# ═══════════════════════════════════════════════════════════════
#  连接检查
# ═══════════════════════════════════════════════════════════════

def is_ldaps(client):
    """判断当前连接是否为 LDAPS 或已 StartTLS。"""
    return bool(client.server.ssl) or getattr(client, 'tls_started', False)


def require_ldaps(client):
    """敏感操作需要 LDAPS，不满足则抛异常。"""
    if not is_ldaps(client):
        raise Exception(
            "This operation requires LDAPS. "
            "Use 'start_tls' or connect via LDAPS (port 636)."
        )


# ═══════════════════════════════════════════════════════════════
#  LDAP 结果处理
# ═══════════════════════════════════════════════════════════════

def check_result(client, success_msg=None):
    """
    检查 LDAP 操作结果，成功时可选打印消息，失败时抛出有意义的异常。
    """
    result = client.result
    code = result.get('result', -1)
    desc = result.get('description', '')
    msg = result.get('message', '')

    if code == 0:
        if success_msg:
            print_success(success_msg)
        return True
    elif code == 50:
        raise Exception('Insufficient rights: %s' % msg)
    elif code == 19:
        raise Exception('Constraint violation: %s' % msg)
    elif code == RESULT_UNWILLING_TO_PERFORM:
        raise Exception('Server unwilling to perform: %s' % msg)
    else:
        raise Exception('LDAP error (%d): %s %s' % (code, desc, msg))


# ═══════════════════════════════════════════════════════════════
#  DN / 对象查询
# ═══════════════════════════════════════════════════════════════

def get_dn(client, domain_dumper, sam_name):
    """
    根据 sAMAccountName 查找 DN。
    如果传入的已经是 DN（包含逗号）则直接返回。
    """
    if "," in sam_name:
        return sam_name
    try:
        client.search(
            domain_dumper.root,
            '(sAMAccountName=%s)' % escape_filter_chars(sam_name),
            attributes=['distinguishedName'],
        )
        return client.entries[0].entry_dn
    except (IndexError, KeyError):
        return None


def get_entry(client, domain_dumper, sam_name, attributes=None, controls=None):
    """
    根据 sAMAccountName 获取完整 LDAP entry。
    返回 ldap3 Entry 或 None。
    """
    attrs = attributes or ['*']
    kwargs = {
        'search_base': domain_dumper.root,
        'search_filter': '(sAMAccountName=%s)' % escape_filter_chars(sam_name),
        'attributes': attrs,
    }
    if controls:
        kwargs['controls'] = controls
    client.search(**kwargs)
    if len(client.entries) == 1:
        return client.entries[0]
    return None


def get_domain_name(base_dn):
    """从 base DN (DC=corp,DC=local) 推导域名 (corp.local)。"""
    domain = re.sub(',DC=', '.', base_dn[base_dn.find('DC='):], flags=re.I)
    return domain[3:]  # 去掉开头的 "DC=" 变成的 "."


def parse_args(line, min_args, max_args=None, usage=""):
    """安全解析 shell 参数，数量不匹配时抛异常。"""
    args = shlex.split(line) if line.strip() else []
    if len(args) < min_args:
        raise Exception("Expected at least %d argument(s). %s" % (min_args, usage))
    if max_args and len(args) > max_args:
        raise Exception("Expected at most %d argument(s). %s" % (max_args, usage))
    return args


# ═══════════════════════════════════════════════════════════════
#  Security Descriptor / ACE 工具
# ═══════════════════════════════════════════════════════════════

def create_empty_sd():
    """创建一个空的 Security Descriptor (仅含 BUILTIN\\Administrators Owner)。"""
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd


def create_allow_ace(sid, mask=0x000f01ff):
    """
    创建 ACCESS_ALLOWED ACE。
    mask 默认 0x000f01ff (Full Control)。
    """
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = mask
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace


# ═══════════════════════════════════════════════════════════════
#  通用显示工具
# ═══════════════════════════════════════════════════════════════

def display_entry(entry, attributes=None):
    """
    以彩色格式显示一个 LDAP entry 的属性。
    如果指定 attributes 则只显示这些属性，否则显示所有非空属性。
    """
    from utils.ui import Fore, Style

    print_found("DN: %s" % entry.entry_dn)
    if attributes:
        for attr in attributes:
            try:
                val = entry[attr].value
                if val is not None:
                    print("  %s%s%s: %s" % (Fore.CYAN, attr, Style.RESET_ALL, val))
            except (KeyError, ldap3.core.exceptions.LDAPAttributeError):
                pass
    else:
        # 显示所有属性
        for attr in entry.entry_attributes:
            try:
                vals = entry[attr].values
                if vals:
                    for v in vals:
                        print("  %s%s%s: %s" % (Fore.CYAN, attr, Style.RESET_ALL, v))
            except (KeyError, ldap3.core.exceptions.LDAPAttributeError):
                pass


def display_entries(entries, attributes=None):
    """批量显示 entry 列表。"""
    from utils.ui import Fore, Style as S

    if not entries:
        print_warn("No results found.")
        return

    for entry in entries:
        display_entry(entry, attributes)
        print(Fore.LIGHTBLACK_EX + "─" * 50)


def print_table(header, rows):
    """打印 impacket 风格横排表格"""
    if not rows:
        return
    col_lens = [max(len(header[i]), max(len(r[i]) for r in rows)) for i in range(len(header))]
    fmt = ' '.join(['{:<%d}' % w for w in col_lens])
    print(fmt.format(*header))
    print(' '.join(['-' * w for w in col_lens]))
    for r in rows:
        print(fmt.format(*r))


# 控制台表格最大显示行数 — 大域 find_* 结果可能成千上万行,
# 全打控制台会刷屏丢记录, 超出部分落盘 report/*.csv
PRINT_ROW_LIMIT = 100


def print_table_capped(header, rows, tag='result', limit=PRINT_ROW_LIMIT,
                       report_dir='report'):
    """
    打印表格, 超过 limit 行时控制台只显示前 limit 行,
    完整结果保存到 <report_dir>/<tag>_<时间戳>.csv 并打印文件路径。
    """
    if len(rows) <= limit:
        print_table(header, rows)
        return

    print_table(header, rows[:limit])

    os.makedirs(report_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_tag = re.sub(r'[^A-Za-z0-9_.-]+', '_', tag)
    path = os.path.join(report_dir, '%s_%s.csv' % (safe_tag, ts))
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    print_warn("Too many rows — showing first %d of %d" % (limit, len(rows)))
    print_success("Full results saved: %s (%d rows)" % (path, len(rows)))



# ═══════════════════════════════════════════════════════════════
#  DNS 解析 (零依赖, 直接 UDP 查询指定 server)
# ═══════════════════════════════════════════════════════════════

def _skip_dns_name(data, offset):
    """跳过 DNS 报文中的域名 (处理指针压缩), 返回下一字段偏移。"""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # 指针压缩 (2 字节)
            return offset + 2
        offset += 1 + length
    return offset


def dns_resolve_a(name, server, timeout=2.0, qid=0x1234):
    """向指定 DNS server 查询 A 记录, 返回 IPv4 列表。

    零依赖: 用 struct + socket 自行构造/解析 DNS 报文 (RFC 1035)。
    先 UDP/53, 失败自动回退 TCP/53 (跨网段/防火墙环境 UDP 常被拦)。
    用于系统 gethostbyname 无法解析 (如本机不在域内) 时直接问 DC。
    失败返回空列表。
    """
    name = (name or '').strip().rstrip('.')
    if not name:
        return []
    # 构造标准递归查询: header(12) + question
    header = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    qname = b''.join(
        bytes([len(lbl)]) + lbl.encode()
        for lbl in name.split('.')
    ) + b'\x00'
    query = header + qname + struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN

    data = b''
    # 先试 UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(2048)
    except Exception:
        data = b''
    finally:
        sock.close()

    # UDP 失败 → TCP 回退 (报文前加 2 字节长度前缀)
    if not data:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout + 1)
        try:
            sock.connect((server, 53))
            sock.sendall(struct.pack('>H', len(query)) + query)
            hdr = b''
            while len(hdr) < 2:
                chunk = sock.recv(2 - len(hdr))
                if not chunk:
                    raise IOError('short read')
                hdr += chunk
            mlen = struct.unpack('>H', hdr)[0]
            while len(data) < mlen:
                chunk = sock.recv(mlen - len(data))
                if not chunk:
                    break
                data += chunk
        except Exception:
            return []
        finally:
            sock.close()

    if len(data) < 12:
        return []
    qdcount = struct.unpack('>H', data[4:6])[0]
    ancount = struct.unpack('>H', data[6:8])[0]

    # 跳过 question section
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    # 解析 answer section, 收集 A 记录
    ips = []
    for _ in range(ancount):
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
            ips.append('.'.join(str(b) for b in data[offset:offset + 4]))
        offset += rdlength
    return ips


def resolve_host_ip(name, dns_server=None):
    """解析主机名为 IPv4, 三级回退:

      1) 本身已是合法 IP → 原样返回
      2) 系统 gethostbyname (运行机在域内时通常即可)
      3) (给定 dns_server 时) 直接向该 server (如 DC) 的 53 端口查 A 记录,
         使非域机器也能解析域内主机名

    解析失败返回 None。
    """
    if not name:
        return None
    name = str(name).strip()
    if not name:
        return None
    # 1. 已是合法 IP
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    # 2. 系统解析
    try:
        return socket.gethostbyname(name)
    except Exception:
        pass
    # 3. 直接问指定 DNS server (DC)
    if dns_server:
        ips = dns_resolve_a(name, dns_server)
        if ips:
            return ips[0]
    return None



# ═══════════════════════════════════════════════════════════════
#  分页查询
# ═══════════════════════════════════════════════════════════════

# 默认分页大小 — AD 默认 sizeLimit 通常是 1000
PAGED_SIZE = 1000


def paged_search(client, search_base, search_filter, attributes=None,
                 paged_size=PAGED_SIZE, controls=None, search_scope=None,
                 progress=False):
    """
    执行 LDAP 分页查询，自动收集所有页的结果。

    ldap3 的 client.search + paged_size=N 会自动处理分页
    (通过 PagedResultsControl)，但需要反复调用以获取后续页。
    此函数封装了完整的分页遍历逻辑。

    参数:
        client       — ldap3.Connection
        search_base  — 搜索基础 DN
        search_filter — LDAP 过滤器
        attributes   — 要返回的属性列表 (默认 ['*'])
        paged_size   — 每页大小 (默认 1000)
        controls     — 额外的 LDAP controls
        progress     — True 时每下载一页打印一次进度(大结果集防"假死")

    返回:
        list[ldap3.Entry] — 所有匹配的 entry 列表
    """
    attrs = attributes or ['*']
    all_entries = []

    kwargs = {
        'search_base': search_base,
        'search_filter': search_filter,
        'attributes': attrs,
        'paged_size': paged_size,
    }
    if controls:
        kwargs['controls'] = controls
    if search_scope:
        kwargs['search_scope'] = search_scope

    if progress:
        print("[*] downloading page 1 ...")
    client.search(**kwargs)
    all_entries.extend(client.entries)
    if progress:
        print("[*] downloaded %d entries ..." % len(all_entries))

    # 继续获取后续页
    # ldap3 将 cookie 存储在 client.result['controls'] 中
    total = len(all_entries)
    page = 1
    while True:
        cookie = None
        try:
            cookie = client.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        except (KeyError, TypeError):
            break
        if not cookie:
            break

        # 必须把 cookie 传回 paged_cookie,否则每次都从第一页重新查 → 死循环
        client.search(paged_cookie=cookie, **kwargs)
        new_entries = client.entries
        if not new_entries:
            break
        all_entries.extend(new_entries)
        total += len(new_entries)
        page += 1
        if progress:
            print("[*] downloaded %d entries (page %d) ..." % (total, page))

        # 安全阀：防止无限循环
        if total > 100000:
            break

    return all_entries
