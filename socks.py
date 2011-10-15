# -*- test-case-name: twisted.test.test_socks -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Implementation of the SOCKSv4 protocol.
"""

# python imports
import struct
import string
import socket
import time

# twisted imports
from twisted.internet import reactor, protocol, defer, abstract
from twisted.python import log


SOCKSv4_REQUEST_VERSION = 4
SOCKSv4_REPLY_VERSION = 0
SOCKSv4_CONNECT_CODE = 1
SOCKSv4_BIND_CODE = 2
SOCKSv4_SUCCESS_CODE = 90
SOCKSv4_REPLY_CODE = {
    90 : "Request granted.",
    91 : "Request rejected or failed.",
    92 : "Request rejected because SOCKS server cannot connect to identd on the client.",
    93 : "Request rejected because the client program and identd report different user-ids."
}

class SOCKSv4Outgoing(protocol.Protocol):

    def __init__(self,socks):
        self.socks=socks

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.socks.makeReply(90, 0, port=peer.port, ip=peer.host)
        self.socks.otherConn=self

    def connectionLost(self, reason):
        self.socks.transport.loseConnection()

    def dataReceived(self,data):
        self.socks.write(data)

    def write(self,data):
        self.socks.log(self,data)
        self.transport.write(data)



class SOCKSv4Incoming(protocol.Protocol):

    def __init__(self,socks):
        self.socks=socks
        self.socks.otherConn=self

    def connectionLost(self, reason):
        self.socks.transport.loseConnection()

    def dataReceived(self,data):
        self.socks.write(data)

    def write(self,data):
        self.socks.log(self,data)
        self.transport.write(data)


class SOCKSv4(protocol.Protocol):
    """
    An implementation of the SOCKSv4 server protocol.

    @type logging: C{str} or C{None}
    @ivar logging: If not C{None}, the name of the logfile to which connection
        information will be written.

    @type reactor: object providing L{twisted.internet.interfaces.IReactorTCP}
    @ivar reactor: The reactor used to create connections.

    @type buf: C{str}
    @ivar buf: Part of a SOCKSv4 connection request.

    @type otherConn: C{SOCKSv4Incoming}, C{SOCKSv4Outgoing} or C{None}
    @ivar otherConn: Until the connection has been established, C{otherConn} is
        C{None}. After that, it is the proxy-to-destination protocol instance
        along which the client's connection is being forwarded.
    """
    def __init__(self, logging=None, reactor=reactor):
        self.logging = logging
        self.reactor = reactor

    def connectionMade(self):
        self.buf = ""
        self.otherConn = None

    def dataReceived(self, data):
        """
        Called whenever data is received.

        @type data: C{str}
        @param data: Part or all of a SOCKSv4 packet.
        """
        if self.otherConn:
            self.otherConn.write(data)
            return
        self.buf = self.buf + data
        completeBuffer = self.buf
        if "\000" in self.buf[8:]:
            head, self.buf = self.buf[:8], self.buf[8:]
            version, code, port = struct.unpack("!BBH", head[:4])
            user, self.buf = self.buf.split("\000", 1)
            if head[4:7] == "\000\000\000" and head[7] != "\000":
                # An IP address of the form 0.0.0.X, where X is non-zero,
                # signifies that this is a SOCKSv4a packet.
                # If the complete packet hasn't been received, restore the
                # buffer and wait for it.
                if "\000" not in self.buf:
                    self.buf = completeBuffer
                    return
                server, self.buf = self.buf.split("\000", 1)
                d = self.reactor.resolve(server)
                d.addCallback(self._dataReceived2, user,
                              version, code, port)
                d.addErrback(lambda result, self = self: self.makeReply(91))
                return
            else:
                server = socket.inet_ntoa(head[4:8])

            self._dataReceived2(server, user, version, code, port)

    def _dataReceived2(self, server, user, version, code, port):
        """
        The second half of the SOCKS connection setup. For a SOCKSv4 packet this
        is after the server address has been extracted from the header. For a
        SOCKSv4a packet this is after the host name has been resolved.

        @type server: C{str}
        @param server: The IP address of the destination, represented as a
            dotted quad.

        @type user: C{str}
        @param user: The username associated with the connection.

        @type version: C{int}
        @param version: The SOCKS protocol version number.

        @type code: C{int}
        @param code: The comand code. 1 means establish a TCP/IP stream
            connection, and 2 means establish a TCP/IP port binding.

        @type port: C{int}
        @param port: The port number associated with the connection.
        """
        assert version == 4, "Bad version code: %s" % version
        if not self.authorize(code, server, port, user):
            self.makeReply(91)
            return
        if code == 1: # CONNECT
            d = self.connectClass(server, port, SOCKSv4Outgoing, self)
            d.addErrback(lambda result, self = self: self.makeReply(91))
        elif code == 2: # BIND
            import pdb; pdb.set_trace()
            d = self.listenClass(0, SOCKSv4IncomingFactory, self, server)
            d.addCallback(lambda (h, p),
                          self = self: self.makeReply(90, 0, p, h))
        else:
            raise RuntimeError, "Bad Connect Code: %s" % code
        assert self.buf == "", "hmm, still stuff in buffer... %s" % repr(
            self.buf)

    def connectionLost(self, reason):
        if self.otherConn:
            self.otherConn.transport.loseConnection()

    def authorize(self,code,server,port,user):
        log.msg("code %s connection to %s:%s (user %s) authorized" % (code,server,port,user))
        return 1

    def connectClass(self, host, port, klass, *args):
        return protocol.ClientCreator(reactor, klass, *args).connectTCP(host,port)

    def listenClass(self, port, klass, *args):
        serv = reactor.listenTCP(port, klass(*args))
        return defer.succeed(serv.getHost()[1:])

    def makeReply(self,reply,version=0,port=0,ip="0.0.0.0"):
        self.transport.write(struct.pack("!BBH",version,reply,port)+socket.inet_aton(ip))
        if reply!=90: self.transport.loseConnection()

    def write(self,data):
        self.log(self,data)
        self.transport.write(data)

    def log(self,proto,data):
        if not self.logging: return
        peer = self.transport.getPeer()
        their_peer = self.otherConn.transport.getPeer()
        f=open(self.logging,"a")
        f.write("%s\t%s:%d %s %s:%d\n"%(time.ctime(),
                                        peer.host,peer.port,
                                        ((proto==self and '<') or '>'),
                                        their_peer.host,their_peer.port))
        while data:
            p,data=data[:16],data[16:]
            f.write(string.join(map(lambda x:'%02X'%ord(x),p),' ')+' ')
            f.write((16-len(p))*3*' ')
            for c in p:
                if len(repr(c))>3: f.write('.')
                else: f.write(c)
            f.write('\n')
        f.write('\n')
        f.close()



class SOCKSv4Factory(protocol.Factory):
    """
    A factory for a SOCKSv4 proxy.

    Constructor accepts one argument, a log file name.
    """

    def __init__(self, log):
        self.logging = log

    def buildProtocol(self, addr):
        return SOCKSv4(self.logging, reactor)



class SOCKSv4IncomingFactory(protocol.Factory):
    """
    A utility class for building protocols for incoming connections.
    """

    def __init__(self, socks, ip):
        self.socks = socks
        self.ip = ip


    def buildProtocol(self, addr):
        if addr[0] == self.ip:
            self.ip = ""
            self.socks.makeReply(90, 0)
            return SOCKSv4Incoming(self.socks)
        elif self.ip == "":
            return None
        else:
            self.socks.makeReply(91, 0)
            self.ip = ""
            return None



class SOCKSError(Exception):
    pass


class AlreadyConnecting(SOCKSError):
    pass


class AlreadyConnected(SOCKSError):
    pass


class AlreadyBinding(SOCKSError):
    pass


class AlreadyBound(SOCKSError):
    pass



from binascii import hexlify
prettyHex = lambda x: ' '.join(['0x'+hexlify(i) for i in x])


class SOCKSv4Client(protocol.Protocol):
    """
    SOCKSv4(a) client protocol.

    Note that a SOCKS client can operate as a TCP client *or server*,
    but in both cases acts as a client to the proxy server.
    """

    def __init__(self, reactor):
        self._reactor = reactor

        self.alreadyConnected = False
        self.alreadyBound = False

        self._connectDeferred = None
        self._bindDeferred = None
        self._bindCount = 0

        self.buf = ""


    def _write(self, data):
        print '->', prettyHex(data)
        self.transport.write(data)


    def dataReceived(self, data):
        print '<-', prettyHex(data)
        self.buf += data

        if len(self.buf) >= 8:
            version, code, port = struct.unpack("!BBH", self.buf[:4])
            ip, self.buf = self.buf[4:8], self.buf[8:]

            if version == SOCKSv4_REPLY_VERSION:
                # SOCKSv4 CONNECT/BIND reply packets are indistinguishable,
                # so check what's expected and process as that
                if self._connectDeferred:
                    self.connectReply(code)
                elif self._bindDeferred:
                    self.bindReply(code, port, ip)
                else:
                    # unexpected reply. lose connection?
                    pass


    def _fail(self, reason):
        self._connectDeferred = None
        self._bindDeferred = None

        return reason


    def _setActualAddress(self, ip):
        self.actualAddress = (ip, self.address[1])


    def _isFree(self):
        if self._connectDeferred:
            return defer.fail(AlreadyConnecting())
        elif self.alreadyConnected:
            return defer.fail(AlreadyConnected())
        elif self._bindDeferred:
            return defer.fail(AlreadyBinding())
        elif self.alreadyBound:
            return defer.fail(AlreadyBound())


    def _actuallySendConnect(self):
        port = self.actualAddress[1]

        frame = struct.pack("!BBHBBBB", SOCKSv4_REQUEST_VERSION,
                            SOCKSv4_CONNECT_CODE, port, *ip)
        frame += self.user + '\000'
        self._write(frame)

        return self._connectDeferred


    def _actuallySendConnect(self):
        self.makeRequest(SOCKSv4_CONNECT_CODE, port=self.actualAddress[1],
                         ip=self.actualAddress[0], user=self.user)

        return self._connectDeferred


    def sendConnect(self, host, port, user):
        """
        Connect to a remote application server via proxy.

        @type host: C{str}
        @param host: The hostname to connect to as a C{str}

        @type port: C{int}
        @param port: The port to connect to as C{int}

        @type user: C{str}
        @param message: The user connecting as a C{str}
        """
        status = self._isFree()
        if status: return status

        self._connectDeferred = defer.Deferred()

        self.address = (host, port)
        self.user = user

        result = self._reactor.resolve(host)
        result.addCallback(self._setActualAddress)
        result.addCallback(lambda _: self._actuallySendConnect())
        result.addErrback(self._fail) # a chance to reset instance variables

        return result


    def _actuallySendBind(self):
        self.makeRequest(SOCKSv4_BIND_CODE, port=self.actualAddress[1],
                         ip=self.actualAddress[0], user=self.user)

        return self._bindDeferred


    def sendBind(self, host, port, user):
        """
        Listen on a local port for connections from a remote application
        server via proxy.

        Note that this function does not bind to the specified address,
        it is the responsibility of the calling party to do this via the
        usual APIs.

        @type host: C{str}
        @param host: The hostname to bind to as a C{str}

        @type port: C{int}
        @param port: The port to bind to as C{int}

        @type user: C{str}
        @param message: The user connecting as a C{str}
        """
        status = self._isFree()
        if status: return status

        self._bindDeferred = defer.Deferred()

        self.address = (host, port)
        self.user = user

        result = self._reactor.resolve(host)
        result.addCallback(self._setActualAddress)
        result.addCallback(lambda _: self._actuallySendBind())
        result.addErrback(self._fail) # a chance to reset instance variables

        return result


    def makeRequest(self, reply, version=SOCKSv4_REQUEST_VERSION, port=0,
                    ip="0.0.0.0", user=""):
        frame = struct.pack("!BBH", version, reply, port) + socket.inet_aton(ip)
        frame += user + '\000'
        self._write(frame)


    def connectReply(self, code):
        # wipe self._connectDeferred *before* firing
        # the deferred incase its callback wants to
        # call sendConnect() again
        d = self._connectDeferred
        self._connectDeferred = None

        if code == SOCKSv4_SUCCESS_CODE:
            self.alreadyConnected = True
            d.callback(SOCKSv4_REPLY_CODE[code])
        else:
            d.errback(SOCKSv4_REPLY_CODE[code])


    def bindReply(self, code, port, ip):
        # wipe self._bindDeferred *before* firing the
        # deferred incase its callback wants to call
        # sendBind() again
        d = self._bindDeferred
        self._bindDeferred = None

        if code == SOCKSv4_SUCCESS_CODE:
            # SOCKS server replies with BIND twice:
            # once to accept the BIND request,
            # and again when it has a connection to
            # the remote application server.
            #
            # A SOCKS client shouldn't start sending
            # application data until after the second
            # BIND.
            self._bindCount +=1

            if self._bindCount == 2:
                self.alreadyBound = True
                d.callback(SOCKSv4_REPLY_CODE[code])
        else:
            d.errback(SOCKSv4_REPLY_CODE[code])



class SOCKSv4ClientFactory(protocol.Factory):
    """
    A factory for a SOCKSv4Client.
    """
    protocol = SOCKSv4Client

    def __init__(self, reactor):
        self._reactor = reactor

    def buildProtocol(self, addr):
        return self.protocol(self._reactor)
