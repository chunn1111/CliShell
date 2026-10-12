#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADCS / WSUS Mixin — ADCS 证书服务发现 + WSUS 服务器发现 (2 个命令)

do_get_adcs   — 企业 CA / 证书模板 / ESC1 漏洞检测 / NTAuth / 根 CA
do_get_wsus   — WSUS 服务器发现 (GPO 扩展 GUID + SPN)
"""

from utils.ui import print_info, print_success, print_found, print_warn, print_header
from utils.helpers import paged_search, resolve_host_ip

# ═══════════════════════════════════════════════════════════════
#  ADCS 常量
# ═══════════════════════════════════════════════════════════════

# EKU OID → 可读名称
EKU_MAP = {
    '1.3.6.1.5.5.7.3.1': 'Server Authentication',
    '1.3.6.1.5.5.7.3.2': 'Client Authentication',
    '1.3.6.1.5.5.7.3.4': 'Secure Email',
    '2.5.29.37.0':       'Any Purpose',
    '1.3.6.1.4.1.311.20.2.2':   'Smart Card Logon',
    '1.3.6.1.4.1.311.10.3.4':   'Encrypting File System',
    '1.3.6.1.4.1.311.10.3.12':  'Document Signing',
    '1.3.6.1.4.1.311.21.6':     'Key Recovery Agent',
}

# msPKI-Certificate-Name-Flag 位
SUBJECT_NAME_FLAGS = {
    0x00000001: 'ENROLLEE_SUPPLIES_SUBJECT',
    0x00000002: 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME',
    0x00010000: 'SUBJECT_ALT_REQUIRE_EMAIL',
    0x00020000: 'SUBJECT_ALT_REQUIRE_UPN',
    0x00040000: 'SUBJECT_ALT_REQUIRE_DNS',
    0x00080000: 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS',
    0x00100000: 'SUBJECT_ALT_REQUIRE_SPN',
    0x00400000: 'SUBJECT_REQUIRE_DNS_AS_CN',
    0x00800000: 'SUBJECT_REQUIRE_EMAIL',
    0x01000000: 'SUBJECT_REQUIRE_UPN',
    0x02000000: 'SUBJECT_REQUIRE_COMMON_NAME',
}

# msPKI-Enrollment-Flag 位
ENROLLMENT_FLAGS = {
    0x00000002: 'PEND_ALL_REQUESTS',
    0x00000020: 'AUTO_ENROLLMENT',
    0x00010000: 'PREVENT_AUTO_ENROLLMENT',
}

# ESC1 漏洞判定: 允许 Client Auth 或 Any Purpose 的 EKU OID
_ESC1_DANGEROUS_EKUS = {
    '1.3.6.1.5.5.7.3.2',    # Client Authentication
    '2.5.29.37.0',           # Any Purpose
}

# WSUS GPO 扩展 GUID
WSUS_EXTENSION_GUIDS = [
    '42B5EAD5-E57D-4C34-8B1D-0559E76B602E',  # Windows Update
    '827D319E-6EAC-444B-9CFC-50549709021C',  # Software Settings / WindowsUpdate
]


# ═══════════════════════════════════════════════════════════════
#  辅助函数
# ═══════════════════════════════════════════════════════════════

def _decode_flags(value, flag_map):
    """将位标志解码为可读名称列表"""
    if not value or not isinstance(value, int):
        return []
    return [name for mask, name in sorted(flag_map.items()) if value & mask]


def _resolve_ekus(eku_oids):
    """将 EKU OID 列表转为可读名称"""
    if not eku_oids:
        return []
    result = []
    for oid in eku_oids:
        result.append(EKU_MAP.get(oid, oid))
    return result


def _safe_attr(entry, attr, default=None):
    """安全读取 entry 属性值"""
    try:
        val = entry[attr].value
        return val if val is not None else default
    except Exception:
        return default


def _safe_attrs(entry, attr):
    """安全读取 entry 属性值列表"""
    try:
        vals = entry[attr].values
        return list(vals) if vals else []
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════
#  AdcsMixin
# ═══════════════════════════════════════════════════════════════

class AdcsMixin:
    """ADCS / WSUS 基础设施发现命令集"""

    # ── 可复用查询方法 (供 dump 调用) ────────────────────────

    def _query_enterprise_cas(self, config_dn):
        """查询企业 CA (Enrollment Services)

        返回 list[dict]: [{caName, dNSHostName, ip, templates}]
        """
        enroll_dn = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,%s' % config_dn
        try:
            entries = paged_search(
                self.client, enroll_dn,
                '(objectClass=pKIEnrollmentService)',
                attributes=['cn', 'dNSHostName', 'certificateTemplates'],
                search_scope='LEVEL',
            )
        except Exception:
            return []

        result = []
        for e in entries:
            ca_name = _safe_attr(e, 'cn', '')
            dns_host = _safe_attr(e, 'dNSHostName', '')
            ip = (resolve_host_ip(dns_host, self.dc_address) or '(unresolved)') if dns_host else ''
            templates = _safe_attrs(e, 'certificateTemplates')
            result.append({
                'caName': ca_name,
                'dNSHostName': dns_host,
                'ip': ip,
                'templates': templates,
            })
        return result

    def _query_cert_templates(self, config_dn):
        """查询证书模板

        返回 list[dict]: [{name, displayName, schemaVersion, enrollmentFlags,
                           subjectNameFlags, ekus, vulnerable}]
        """
        tpl_dn = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,%s' % config_dn
        try:
            entries = paged_search(
                self.client, tpl_dn,
                '(objectClass=pKICertificateTemplate)',
                attributes=[
                    'cn', 'displayName',
                    'msPKI-Template-Schema-Version',
                    'msPKI-Enrollment-Flag',
                    'msPKI-Certificate-Name-Flag',
                    'pKIExtendedKeyUsage',
                ],
                search_scope='LEVEL',
            )
        except Exception:
            return []

        result = []
        for e in entries:
            name = _safe_attr(e, 'cn', '')
            display_name = _safe_attr(e, 'displayName', '')
            schema_ver = _safe_attr(e, 'msPKI-Template-Schema-Version', 0)
            enroll_flag = _safe_attr(e, 'msPKI-Enrollment-Flag', 0) or 0
            subject_flag = _safe_attr(e, 'msPKI-Certificate-Name-Flag', 0) or 0
            eku_oids = _safe_attrs(e, 'pKIExtendedKeyUsage')

            enroll_names = _decode_flags(enroll_flag, ENROLLMENT_FLAGS)
            subject_names = _decode_flags(subject_flag, SUBJECT_NAME_FLAGS)
            eku_names = _resolve_ekus(eku_oids)

            # ESC1 漏洞检测:
            # ENROLLEE_SUPPLIES_SUBJECT 标志 + Client Auth / Any Purpose EKU
            has_supply_subject = bool(subject_flag & 0x00000001)
            has_dangerous_eku = bool(set(eku_oids) & _ESC1_DANGEROUS_EKUS)
            vulnerable = has_supply_subject and has_dangerous_eku

            result.append({
                'name': name,
                'displayName': display_name,
                'schemaVersion': schema_ver,
                'enrollmentFlags': enroll_names,
                'subjectNameFlags': subject_names,
                'ekus': eku_names,
                'vulnerable': vulnerable,
            })
        return result

    def _query_root_cas(self, config_dn):
        """查询根 CA (Certification Authorities)

        返回 list[dict]: [{caName}]
        """
        ca_dn = 'CN=Certification Authorities,CN=Public Key Services,CN=Services,%s' % config_dn
        try:
            entries = paged_search(
                self.client, ca_dn,
                '(objectClass=certificationAuthority)',
                attributes=['cn'],
                search_scope='LEVEL',
            )
        except Exception:
            return []

        result = []
        for e in entries:
            result.append({'caName': _safe_attr(e, 'cn', '')})
        return result

    def _query_ntauth(self, config_dn):
        """查询 NTAuthCertificates — 域认证信任的 CA

        返回 int: 受信任 CA 证书数量
        """
        ntauth_dn = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s' % config_dn
        try:
            self.client.search(
                ntauth_dn,
                '(objectClass=*)',
                attributes=['cACertificate'],
                search_scope='BASE',
            )
            if self.client.entries:
                certs = _safe_attrs(self.client.entries[0], 'cACertificate')
                return len(certs)
        except Exception:
            pass
        return 0

    # ── get_adcs ─────────────────────────────────────────────

    def do_get_adcs(self, line):
        """get_adcs — ADCS 综合信息 (企业CA / 模板 / ESC1漏洞 / NTAuth / 根CA)"""
        config_dn = self._get_config_dn()
        if not config_dn:
            print_warn("Unable to get Configuration naming context")
            return

        print_info("Querying ADCS configuration...")

        # ── 1. 企业 CA ───────────────────────────────────────
        cas = self._query_enterprise_cas(config_dn)
        if cas:
            print_header("Enterprise CAs (%d)" % len(cas))
            for ca in cas:
                print_found("  %-25s  DNS: %-30s  IP: %s" % (
                    ca['caName'], ca['dNSHostName'], ca['ip']))
                if ca['templates']:
                    print_info("    Published templates (%d): %s" % (
                        len(ca['templates']),
                        ', '.join(ca['templates'][:10]) + ('...' if len(ca['templates']) > 10 else ''),
                    ))
        else:
            print_warn("No Enterprise CAs found (ADCS may not be installed)")

        # ── 2. 证书模板 ──────────────────────────────────────
        templates = self._query_cert_templates(config_dn)
        if templates:
            print_header("Certificate Templates (%d)" % len(templates))
            vuln_count = 0
            for tpl in templates:
                vuln_marker = ''
                if tpl['vulnerable']:
                    vuln_marker = ' [ESC1 VULNERABLE]'
                    vuln_count += 1

                line = "  %-30s  Schema: v%s" % (tpl['name'], tpl['schemaVersion'])
                if tpl['displayName']:
                    line += "  (%s)" % tpl['displayName']
                print_found(line + vuln_marker)

                if tpl['ekus']:
                    print_info("    EKUs: %s" % ', '.join(tpl['ekus']))
                if tpl['subjectNameFlags']:
                    print_info("    SubjectFlags: %s" % ', '.join(tpl['subjectNameFlags']))
                if tpl['enrollmentFlags']:
                    print_info("    EnrollmentFlags: %s" % ', '.join(tpl['enrollmentFlags']))

            if vuln_count:
                print_warn("  !! %d template(s) with ESC1 vulnerability detected !!" % vuln_count)
        else:
            print_info("No certificate templates found")

        # ── 3. 根 CA ─────────────────────────────────────────
        root_cas = self._query_root_cas(config_dn)
        if root_cas:
            print_header("Root CAs (%d)" % len(root_cas))
            for ca in root_cas:
                print_found("  %s" % ca['caName'])

        # ── 4. NTAuthCertificates ────────────────────────────
        ntauth_count = self._query_ntauth(config_dn)
        print_header("NTAuthCertificates")
        print_info("  Trusted CAs for domain auth: %d" % ntauth_count)

        # ── 5. CA↔Template 交叉映射 ──────────────────────────
        if cas and templates:
            tpl_names = {t['name'] for t in templates}
            published = {ca['caName']: [t for t in ca['templates'] if t in tpl_names] for ca in cas}
            print_header("CA → Template Mapping")
            for ca_name, ca_tpls in published.items():
                print_info("  %-25s → %s" % (
                    ca_name,
                    ', '.join(ca_tpls[:15]) + ('...' if len(ca_tpls) > 15 else '') if ca_tpls else '(none)',
                ))

    # ── get_wsus ─────────────────────────────────────────────

    def do_get_wsus(self, line):
        """get_wsus — WSUS 服务器发现 (GPO 扩展 + SPN)"""
        print_info("Searching WSUS configuration...")

        found = False

        # ── 1. GPO 扩展 GUID 查找 ────────────────────────────
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'gPCMachineExtensionNames', 'distinguishedName'],
        )

        wsus_gpos = []
        for e in entries:
            ext_str = _safe_attr(e, 'gPCMachineExtensionNames', '') or ''
            if not ext_str:
                continue
            for guid in WSUS_EXTENSION_GUIDS:
                if guid.lower() in ext_str.lower():
                    gpo_name = _safe_attr(e, 'displayName', '') or _safe_attr(e, 'cn', '')
                    wsus_gpos.append({
                        'name': gpo_name,
                        'dn': e.entry_dn,
                        'guid': guid,
                    })
                    break

        if wsus_gpos:
            found = True
            print_header("WSUS-related GPOs (%d)" % len(wsus_gpos))
            for gpo in wsus_gpos:
                print_found("  %-35s  GUID: %s" % (gpo['name'], gpo['guid']))
                print_info("    DN: %s" % gpo['dn'])
            print_warn("  Note: WSUS URL (WUServer) is stored in GPO registry policy file on SYSVOL,")
            print_warn("        not directly in LDAP. Check SYSVOL\\\\Policies\\\\<GUID>\\\\Machine\\\\Registry.pol")

        # ── 2. SPN 查找 ──────────────────────────────────────
        for spn_filter in ['(servicePrincipalName=*WSUS*)',
                           '(servicePrincipalName=*WindowsUpdate*)',
                           '(servicePrincipalName=*wsus*)']:
            try:
                self.client.search(
                    self.domain_dumper.root,
                    spn_filter,
                    attributes=['sAMAccountName', 'dNSHostName', 'servicePrincipalName'],
                )
                for e in self.client.entries:
                    found = True
                    name = _safe_attr(e, 'sAMAccountName', '')
                    dns = _safe_attr(e, 'dNSHostName', '')
                    spns = _safe_attrs(e, 'servicePrincipalName')
                    wsus_spns = [s for s in spns if 'wsus' in s.lower() or 'windowsupdate' in s.lower()]
                    if wsus_spns:
                        print_header("WSUS Service Principal Name")
                        print_found("  Account: %s" % name)
                        if dns:
                            print_info("  DNS: %s  IP: %s" % (dns, resolve_host_ip(dns, self.dc_address) or '(unresolved)'))
                        for spn in wsus_spns:
                            print_info("  SPN: %s" % spn)
            except Exception:
                pass

        if not found:
            print_warn("No WSUS configuration found in GPOs or SPNs")
