# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from paramiko.message import Message
from paramiko.pkey import PKey, register_pkey_type
from paramiko.ssh_exception import SSHException


@register_pkey_type
class Ed25519Key(PKey):
    """
    Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.

    .. note::
        Ed25519 key support was added to OpenSSH in version 6.5.

    .. versionadded:: 2.2
    .. versionchanged:: 2.3
        Added a ``file_obj`` parameter to match other key classes.
    """

    # Legacy file format does not support Ed25519
    LEGACY_TYPE = None
    OPENSSH_TYPE_PREFIX = 'ssh-ed25519'

    @staticmethod
    def is_supported():
        """
        Check if the openssl version pyca/cryptography is linked against
        supports Ed25519 keys.
        """
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(b"\x00" * 32)
        except UnsupportedAlgorithm:
            return False  # openssl < 1.1.0
        return True

    def __init__(self, msg=None, data=None, filename=None, password=None,
                 file_obj=None, _raw=None):
        self.public_blob = None
        verifying_key = None
        signing_key = None

        if msg is None and data is not None:
            msg = Message(data)
        if msg is not None:
            self._check_type_and_load_cert(
                msg=msg,
                key_type="ssh-ed25519",
                cert_type="ssh-ed25519-cert-v01@openssh.com",
            )
            verifying_key = ed25519.Ed25519PublicKey.from_public_bytes(msg.get_binary())
        elif filename is not None:
            _raw = self._from_private_key_file(filename, password)
        elif file_obj is not None:
            _raw = self._from_private_key(file_obj, password)
        if _raw is not None:
            signing_key = self._decode_key(_raw)

        if signing_key is None and verifying_key is None:
            raise ValueError("need a key")

        self._signing_key = signing_key
        self._verifying_key = verifying_key or signing_key.public_key()

    def _decode_key(self, _raw):
        pkformat, data = _raw
        if pkformat != self.FORMAT_OPENSSH:
            raise SSHException("Invalid key format")

        message = Message(data)
        public = message.get_binary()
        key_data = message.get_binary()
        comment = message.get_binary()  # noqa: F841

        # The second half of the key data is yet another copy of the public key...
        signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])

        # Verify that all the public keys are the same...
        derived_public = signing_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if public != key_data[32:] or public != derived_public:
            raise SSHException("Invalid key public part mis-match")

        return signing_key

    def asbytes(self):
        public_bytes = self._verifying_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        m = Message()
        m.add_string("ssh-ed25519")
        m.add_string(public_bytes)
        return m.asbytes()

    def get_name(self):
        return "ssh-ed25519"

    def get_bits(self):
        return 256

    def can_sign(self):
        return self._signing_key is not None

    def sign_ssh_data(self, data):
        m = Message()
        m.add_string("ssh-ed25519")
        m.add_string(self._signing_key.sign(data))
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != "ssh-ed25519":
            return False
        try:
            self._verifying_key.verify(msg.get_binary(), data)
        except InvalidSignature:
            return False
        else:
            return True
