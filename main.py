import tempfile
import logging
from collections import namedtuple
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

CertAttributes = namedtuple('CertAttributes', [
    'country',
    'state',
    'city',
    'org',
    'org_name',
    'common'
])


class Cert():
    """Cert class helps in the generation of SSL certificates."""

    def __init__(self, attributes=None):

        # Accept the attributes that define the certs.
        if attributes:
            self.attributes = attributes

    def _private_key():
        """Generates a private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def _certificate(self, certattrs, ca_cert=False):
        """Generate a certificate."""
        if not certattrs:
            certattrs = self.attributes

        key = self._private_key()

        # Create certificate and sign it.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, certattrs.country),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, certattrs.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, certattrs.city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, certattrs.org),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, certattrs.org_name),
            x509.NameAttribute(NameOID.COMMON_NAME, certattrs.common),
        ])
        cert = x509.CertificateBuilder()\
            .subject_name(subject)\
            .issuer_name(issuer)\
            .public_key(key.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(certattrs.common)]),
                critical=False
            )

        if ca_cert:
            cert = cert.add_extension(
                x509.BasicConstraints(
                    ca=True,
                    path_length=1
                ),
                critical=True
            )
        cert = cert.sign(key, hashes.SHA256(), default_backend())

        return key, cert

    def gen_self_signed_cert(self):
        """Generates a self signed cert."""

        return self._certificate(self.attributes)

    def gen_ca_cert(self):
        """
        Generate a key + certificate authority certificate.

        Creates a CA cert for the proxy to use when bumping SSL. This certificate
        is also used to sign an SSL server certificate for the proxy web interface.
        This leverages the trust that must be in place for the ca certificate.
        """
        return self._certificate(self.attributes, ca_cert=True)

    def gen_csr(self):
        """
        Generates a CSR that is based on the passed in key.

        Returns a private key and a CSR.
        """
        certattrs = self.attributes

        key = self.private_key()

        # Generate a CSR.
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                    # Pass in the callers attributes.
                    x509.NameAttribute(
                        NameOID.COUNTRY_NAME, certattrs.country),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, certattrs.state),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, certattrs.city),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, certattrs.org),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, certattrs.org_name),
                    x509.NameAttribute(NameOID.COMMON_NAME, certattrs.common),
                ])).add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(certattrs.common),
                    ]),
                    critical=False,
                )

        # Sign CSR with our private key and return it.
        return key, csr.sign(key, hashes.SHA256(), default_backend())

    # DISK SAVING FUNCTIONS

    def save_key(fobj, key, format='key'):
        """Save a key file."""
        LOGGER.debug('Writing PEM encoded key to %s', fobj.name)
        fobj.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        fobj.write(b'\n')

    def save_cert(fobj, cert, format='pem'):
        """Save a cert."""
        LOGGER.debug('Writing PEM encoded certificate to %s', fobj.name)
        fobj.write(cert.public_bytes(serialization.Encoding.PEM))
        fobj.write(b'\n')

    def save_csr(fobj, csr, format='pem'):
        """Save a csr."""
        LOGGER.debug('Writing PEM encoded CSR to %s', fobj.name)
        fobj.write(csr.public_bytes(serialization.Encoding.PEM))
        fobj.write(b'\n')

