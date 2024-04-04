# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Socks Proxy for the WinRM(S) Protocol
#
#   A simple SOCKS server that proxies a connection to relayed WinRM(S) connections
#
# Author:
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
#  Modified: Joe Mondloch <jmk@foofus.net>
#
from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksplugins.winrm import WinRMSocksRelay
from impacket.examples.ntlmrelayx.utils.ssl import SSLServerMixin
from OpenSSL import SSL

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "WinRMSSocksRelay"
EOL = '\r\n'

class WinRMSSocksRelay(SSLServerMixin, WinRMSocksRelay):
    PLUGIN_NAME = 'WinRMS Socks Plugin'
    PLUGIN_SCHEME = 'WINRMS'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        WinRMSocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 5986 

    def skipAuthentication(self):
        LOG.debug('Wrapping client connection in TLS/SSL')
        self.wrapClientConnection()
        if not WinRMSocksRelay.skipAuthentication(self):
            # Shut down TLS connection
            self.socksSocket.shutdown()
            return False
        return True

    def tunnelConnection(self):
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
            except SSL.ZeroReturnError:
                # The SSL connection was closed, return
                return
            # Pass the request to the server
            tosend = self.prepareRequest(data)
            self.relaySocket.send(tosend)
            # Send the response back to the client
            self.transferResponse()
