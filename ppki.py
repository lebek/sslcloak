"""
TLS is used for encryption purposes, but also for bidirectional authentication.
This module takes care of creating the necessary keys and certificates for both
the server and client.
"""

from OpenSSL import crypto
import os


CA_CN = 'sslcloak-ca'
BRIDGE_CN = 'sslcloak-bridge'
LOCAL_CN = 'sslcloak-local'


class PrivatePKI(object):

    def __init__(self, caCommonName, caKeyFile=None, caCertFile=None):
        self.nextSerialNumber = 0
        self.ca = self._createCA(caCommonName, caKeyFile, caCertFile)

    def _writeSubjectDefaults(self, subject, commonName):
        subject.countryName = 'US'
        subject.stateOrProvinceName = 'San Francisco'
        subject.organizationName = 'sslcloak'
        subject.organizationalUnitName = 'installation'
        subject.commonName = commonName

    def generateKeyPair(self, saveFile=None):
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)

        if saveFile:
            fd = os.open(saveFile, os.O_RDWR|os.O_CREAT, 0600)
            os.write(fd, (crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)))
            os.close(fd)

        return pkey

    def generateCSR(self, pkey, commonName, saveFile=None):
        request = crypto.X509Req()
        self._writeSubjectDefaults(request.get_subject(), commonName)

        request.set_pubkey(pkey)
        request.sign(pkey, 'md5')

        if saveFile:
            fd = os.open(saveFile, os.O_RDWR|os.O_CREAT, 0644)
            os.write(fd, crypto.dump_certificate_request(
                crypto.FILETYPE_PEM, request))
            os.close(fd)

        return request

    def _createCert(self, commonName, issuer=None, keyFile=None, certFile=None):
        key = self.generateKeyPair(keyFile)

        # XXX TODO is this intermediate CSR necessary?
        req = self.generateCSR(key, commonName)

        cert = crypto.X509()

        cert.set_serial_number(self.nextSerialNumber)
        self.nextSerialNumber += 1

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)

        if issuer:
            cert.set_issuer(issuer[0].get_subject())
        else: # self-signed
            cert.set_issuer(req.get_subject())

        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        if issuer:
            cert.sign(issuer[1], 'md5')
        else:
            cert.sign(key, 'md5')

        if certFile:
            fd = open(certFile, 'w')
            fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            fd.close()

        return (cert, key)

    def _createCA(self, commonName, keyFile=None, certFile=None):
        return self._createCert(commonName, keyFile=keyFile, certFile=certFile)

    def addCert(self, commonName, keyFile=None, certFile=None):
        return self._createCert(commonName, issuer=self.ca,
                                keyFile=keyFile, certFile=certFile)


if __name__ == "__main__":
    p = PrivatePKI(CA_CN, caKeyFile='cakey.pem', caCertFile='cacert.pem')
    b = p.addCert(BRIDGE_CN, keyFile='bridgekey.pem', certFile='bridgecert.pem')
    l = p.addCert(LOCAL_CN, keyFile='localkey.pem', certFile='localcert.pem')


