#! /usr/bin/python
from twisted.internet import reactor, endpoints, protocol
import socks

from sslcontext import ServerContextFactory

class SOCKSv4Factory(protocol.Factory):
    def __init__(self, log):
        self.logging = log

    def buildProtocol(self, addr):
        return socks.SOCKSv4(self.logging, reactor)

if '__main__' == __name__:
    from sys import argv

    listenPort = int(argv[1])
    contextFactory = ServerContextFactory("bridgekey.pem", "bridgecert.pem",
                                          "cacert.pem", ["sslcloak-local"])
    point = endpoints.SSL4ServerEndpoint(reactor, listenPort, contextFactory)
    point.listen(SOCKSv4Factory("socks.log"))
    reactor.run()
