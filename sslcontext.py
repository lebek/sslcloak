from OpenSSL import SSL

from twisted.internet import ssl


class VerifyMixin:

    def _printError(self, msg, x509, errnum, errdepth):
        commonName = x509.get_subject().commonName
        print "ERROR %s: CN %s, errnum: %d, errdepth: %d" % (msg, commonName, 
                                                             errnum, errdepth)

    def _verifyCallback(self, connection, x509, errnum, errdepth, ok):
        commonName = x509.get_subject().commonName
        if ok:
            if errdepth == 0 and not commonName in self.allowedCommonNames:
                self._printError("commonName", x509, errnum, errdepth)
                return False
            return True
        else:
            self._printError("Certificate verification", x509, errnum, 
                             errdepth)
            return False


class ServerContextFactory(ssl.DefaultOpenSSLContextFactory, VerifyMixin):
    """
    DefaultOpenSSLContextFactory which uses TLSv1_METHOD by default and takes
    a trusted CA cerificate file in the constructor, along with a list of
    commonNames to accept in client certificate verification.
    """

    def __init__(self, keyFile, certFile, caCertFile, allowedCommonNames,
                 sslMethod=SSL.TLSv1_METHOD, contextFactory=SSL.Context):
        self.caCertFile = caCertFile
        self.allowedCommonNames = allowedCommonNames
        ssl.DefaultOpenSSLContextFactory.__init__(
            self, keyFile, certFile, sslmethod=sslMethod,
            _contextFactory=contextFactory)

    def cacheContext(self):
        if self._context is None:
            ctx = self._contextFactory(self.sslmethod)
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.use_certificate_file(self.certificateFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)
            ctx.load_verify_locations(self.caCertFile)
            ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           self._verifyCallback)
            self._context = ctx


class ClientContextFactory(VerifyMixin):
    """
    Client context factory which uses TLSv1_METHOD by default and takes client
    key/certificate file and trusted CA cerificate file in the constructor,
    along with a list of commonNames to accept in server certificate
    verification.
    """

    def __init__(self, keyFile, certFile, caCertFile, allowedCommonNames,
                 sslMethod=SSL.TLSv1_METHOD, contextFactory=SSL.Context):
        self.keyFile = keyFile
        self.certFile = certFile
        self.caCertFile = caCertFile
        self.allowedCommonNames = allowedCommonNames
        self.sslmethod = sslMethod
        self._contextFactory = contextFactory

    def getContext(self):
        ctx = self._contextFactory(self.sslmethod)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.use_certificate_file(self.certFile)
        ctx.use_privatekey_file(self.keyFile)
        ctx.load_verify_locations(self.caCertFile)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                       self._verifyCallback)
        return ctx

