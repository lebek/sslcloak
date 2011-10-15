from twisted.internet import reactor, endpoints, protocol
import socks

class Outgoing(protocol.Protocol):

    def __init__(self, incoming):
        self.incoming = incoming

    def connectionMade(self):
        print 'made conn to outgoing server'

    def dataReceived(self, data):
        print 'FROM OUT: ', data
        self.incoming.transport.write(data)

class Incoming(protocol.Protocol):

    def connectionMade(self):
        print 'conn made'
        self.address = self.transport.getHost()

        # binding to 9999 identifies our traffic to the local firewall
        # as proxy traffic (i.e. let me through). this is no good because
        # only one connection can be made at a time, since ports can only be
        # bound once. also, 9999 only identifies us by obscurity - i.e. any
        # application could bind to 9999 and pass.
        #
        # XXX TODO instead, identify our traffic as proxy traffic using the
        # dst-port - i.e. the SOCKS server port
        point = endpoints.TCP4ClientEndpoint(reactor, self.address.host,
                                             self.address.port,
                                             bindAddress=('109.175.151.84', 9999))
        point.connect(OutgoingFactory(self))
        # need to stop incoming from writing to this until connection made

    def dataReceived(self, data):
        print 'FROM IN: ', data
        self.outgoing.transport.write(data)

class IncomingFactory(protocol.Factory):

    def buildProtocol(self, addr):
        return Incoming()

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
    point = endpoints.TCP4ServerEndpoint(reactor, listenPort)
    d = point.listen(IncomingFactory())
    def listening(a):
        print a
    d.addCallback(listening)
    reactor.run()
