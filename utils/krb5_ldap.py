#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kerberos (GSS-SPNEGO) LDAP 登录 — 使用 impacket 自实现的 Kerberos,
不依赖系统 GSSAPI。解决两类 ldap3 原生 SASL 不兼容场景:

  1. 老 DC (2008 R2 等) 拒绝 ldap3 的 NTLM(SICILY) 绑定
  2. RC4 票据 + 系统 Heimdal GSSAPI 报 "Message stream modified"

由 CliShell -k 调用,票据来源: KRB5CCNAME (或哈希/密码现场取 TGT)。
移植自 noPac/utils/helper.py 的 ldap3_kerberos_login。
"""
import os
import logging
from binascii import unhexlify

import ldap3


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='',
                         kdcHost=None, useCache=False):
    """对 ldap3.Connection 执行 Kerberos(GSS-SPNEGO)绑定。失败抛异常。"""
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
    import datetime

    TGT = TGS = None

    if lmhash or nthash:
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    if useCache:
        ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        if domain == '':
            domain = ccache.principal.realm['data'].decode('utf-8')
        logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
        principal = 'ldap/%s@%s' % (target.upper(), domain.upper())
        creds = ccache.getCredential(principal)
        if creds is None:
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug('Using TGT from cache')
            else:
                raise Exception('No valid credentials found in ccache')
        else:
            TGS = creds.toTGS(principal)
            logging.debug('Using TGS from cache')
        if user == '' and creds is not None:
            user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
        elif user == '' and len(ccache.principal.components) > 0:
            user = ccache.principal.components[0]['data'].decode('utf-8')

    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    if TGT is None and TGS is None:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                aesKey, kdcHost)
    elif TGT is not None:
        tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
    else:
        tgs, cipher, sessionKey = TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey']

    # 构造 NegTokenInit + AP_REQ
    blob = SPNEGO_NegTokenInit()
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    apReq['ap-options'] = constants.encodeFlags([])
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)
    # Key Usage 11: AP-REQ Authenticator
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    if connection.closed:
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True
    return True
