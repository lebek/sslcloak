from twisted.internet import reactor, endpoints, protocol
import socks

import pdb

from binascii import hexlify
def prettyHex(bytes, width, cutoff=None):
    cut = cutoff and len(bytes) > cutoff
    if cut: bytes = bytes[:cutoff]
    h = [hexlify(i) for i in bytes]
    hs = [' '.join(h[i:i+width]) for i in range(0, len(h), width)]
    if cut: hs[-1] += ' [...]'
    return '\n'.join(hs)

def switchProtocol(transport, newProtocol):
    transport.protocol = newProtocol
    newProtocol.transport = transport
    newProtocol.connectionMade()

class Outgoing(protocol.Protocol):

    def __init__(self, incoming):
        self.incoming = incoming

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        addr = self.incoming.address
        print "%s:%d SAYS\n%s\n" % (addr.host, addr.port, prettyHex(data, 16, 10))
        self.incoming.transport.write(data)

class Incoming(protocol.Protocol):

    def __init__(self, socksHost, socksPort, contextFactory):
        self.socksHost = socksHost
        self.socksPort = socksPort
        self.contextFactory = contextFactory

    def connectionMade(self):
        self.address = self.transport.getHost()

        # binding to 9999 identifies our traffic to the local firewall
        # as proxy traffic (i.e. let me through). this is no good because
        # only one connection can be made at a time, since ports can only be
        # bound once. also, 9999 only identifies us by obscurity - i.e. any
        # application could bind to 9999 and pass.
        #
        # XXX TODO instead, identify our traffic as proxy traffic using the
        # dst-port - i.e. the SOCKS server port
        #point = endpoints.TCP4ClientEndpoint(reactor, self.address.host,
        #                                     self.address.port,
        #                                     bindAddress=(BIND_ADDR, BIND_PORT))
        factory = socks.SOCKSv4ClientFactory(reactor)
        point = endpoints.SSL4ClientEndpoint(reactor, self.socksHost,
                                             self.socksPort,
                                             self.contextFactory)
        d = point.connect(factory)

        def connected(p):
            d = p.sendConnect(self.address.host, self.address.port, "ignored")
            self.outgoing = Outgoing(self)
            d.addCallback(lambda _: switchProtocol(p.transport, self.outgoing))

        d.addCallbacks(connected, lambda x: pdb.set_trace())

        #point.connect(OutgoingFactory(self))
        # need to stop incoming from writing to this until connection made

    def dataReceived(self, data):
        peer = self.transport.getPeer()
        print "%s:%d SAYS\n%s\n" % (peer.host, peer.port, prettyHex(data, 16, 10))
        self.outgoing.transport.write(data)

class IncomingFactory(protocol.Factory):

    def __init__(self, socksHost, socksPort, contextFactory):
        self.socksHost = socksHost
        self.socksPort = socksPort
        self.contextFactory = contextFactory

    def buildProtocol(self, addr):
        return Incoming(self.socksHost, 
                        self.socksPort, 
                        self.contextFactory)

class OutgoingFactory(protocol.Factory):

    def __init__(self, incoming):
        self.incoming = incoming

    def buildProtocol(self, addr):
        outgoing = Outgoing(self.incoming)
        self.incoming.outgoing = outgoing
        return outgoing

if __name__ == "__main__":
    from sys import argv

    listenPort = int(argv[1])
    socksHost = argv[2]
    socksPort = int(argv[3])
    contextFactory = ClientContextFactory("localkey.pem", "localcert.pem",
                                          "cacert.pem", ["sslcloak-bridge"])
    point = endpoints.TCP4ServerEndpoint(reactor, listenPort)
    d = point.listen(IncomingFactory(socksHost, socksHost, contextFactory))
    reactor.run()
