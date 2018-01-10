
from collections import namedtuple

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


    def gen_self_signed_cert():
        """Generates a self signed cert."""