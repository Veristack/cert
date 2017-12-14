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


def load_certificate(f, passphrase=None):
    """
    Ensure we can load the public and private keys from the given file.

    Then write them back out without a passphrase.
    """
    passphrase = passphrase if passphrase else None
    try:
        cert_data = f.read()
    except Exception as e:
        raise IOError('Error reading certificate file: %s' % str(e))
    try:
        key = serialization.load_pem_private_key(
            cert_data,
            passphrase,
            default_backend()
        )
    except Exception as e:
        raise Exception('Error loading key from certificate file: %s' % str(e))
    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        raise Exception('Error loading certificate file: %s' % str(e))
    # Validate the datetimes.
    assert cert.not_valid_before < datetime.utcnow(), \
           'Certificate not valid before %s' % cert.not_valid_before
    assert cert.not_valid_after > datetime.utcnow(), \
           'Certificate expired %s' % cert.not_valid_after
    # TODO: validate that the file contains intermediaries too!
    LOGGER.debug('Certificate details')
    LOGGER.debug('-------------------')
    for a in cert.subject:
        LOGGER.debug('Subject: %s', a)
    for a in cert.issuer:
        LOGGER.debug('Issuer: %s', a)
    for a in cert.extensions:
        LOGGER.debug('Extension: %s', a)
    LOGGER.debug('-------------------')

    return key, cert


# DISK SAVING


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


# CERTIFICATE GENERATION


def private_key():
    """Generates a private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def certificate(certattrs, ca_cert=False):
    """Generate a certificate."""
    key = private_key()

    # Create certificate and sign it.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, certattrs.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, certattrs.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, certattrs.city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, certattrs.org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                           certattrs.org_name),
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


def ss_certificate(certattrs):
    """
    Generate a self signed key + certificate.

    Creates a self signed cert for the proxy to use when bumping SSL. This
    certificate is also used to sign an SSL server certificate for the web
    interface.
    """
    return certificate(certattrs, ca_cert=False)


def ca_certificate(certattrs):
    """
    Generate a key + certificate authority certificate.

    Creates a CA cert for the proxy to use when bumping SSL. This certificate
    is also used to sign an SSL server certificate for the proxy web interface.
    This leverages the trust that must be in place for the ca certificate.
    """
    return certificate(certattrs, ca_cert=True)


def server_certificate(ca_key, ca_cert, common=None):
    """
    Generate server SSL certificate.

    Uses the CA certificate to sign a new SSL certificate for the proxy. All of
    the CA certificate attributes are copied, although the common name can be
    overridden if provided.
    """
    # Extract attributes from ca certificate.

    # Helper function
    def _get_cert_attribute(oid):
        l = ca_cert.issuer.get_attributes_for_oid(oid)
        if l:
            return l[0].value

    attributes = []
    for oid in (
            NameOID.COUNTRY_NAME, NameOID.STATE_OR_PROVINCE_NAME,
            NameOID.LOCALITY_NAME, NameOID.ORGANIZATION_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME
        ):
        value = _get_cert_attribute(oid)
        if value:
            attributes.append(x509.NameAttribute(oid, value))

    if common is None:
        common = _get_cert_attribute(NameOID.COMMON_NAME)
    if common:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common))

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Create certificate and sign it.
    subject = x509.Name(attributes)
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common)]),
                       critical=False)\
        .sign(ca_key, hashes.SHA256(), default_backend())

    return key, cert


# CERTIFICATE SIGNING REQUEST GENERATION


def certificate_signing_request(certattrs):
    """
    Generates a CSR that is based on the passed in key.

    Returns a private key and a CSR.
    """

    key = private_key()

    # Generate a CSR.
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                # Pass in the callers attributes.
                x509.NameAttribute(NameOID.COUNTRY_NAME, certattrs.country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                                   certattrs.state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, certattrs.city),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, certattrs.org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   certattrs.org_name),
                x509.NameAttribute(NameOID.COMMON_NAME, certattrs.common),
            ])).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(certattrs.common),
                ]),
                critical=False,
            )

    # Sign CSR with our private key and return it.
    return key, csr.sign(key, hashes.SHA256(), default_backend())
