# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
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

"""
SSH client & key policies
"""

import getpass
import inspect
import os
import socket
import warnings

from paramiko.agent import Agent
from paramiko.common import DEBUG
from paramiko.config import SSH_PORT
from paramiko.dsskey import DSSKey
from paramiko.rsakey import RSAKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.pkey import load_private_key_file
from paramiko.hostkeys import HostKeys
from paramiko.py3compat import string_types
from paramiko.ssh_exception import SSHException, BadHostKeyException, BadAuthenticationType
from paramiko.transport import Transport, SecurityOptions
from paramiko.util import retry_on_signal, ClosingContextManager


class SSHClient (ClosingContextManager):
    """
    A high-level representation of a session with an SSH server.  This class
    wraps `.Transport`, `.Channel`, and `.SFTPClient` to take care of most
    aspects of authenticating and opening channels.  A typical use case is::

        client = SSHClient()
        client.load_system_host_keys()
        client.connect('ssh.example.com')
        stdin, stdout, stderr = client.exec_command('ls -l')

    You may pass in explicit overrides for authentication and server host key
    checking.  The default mechanism is to try to use local key files or an
    SSH agent (if one is running).

    Instances of this class may be used as context managers.

    .. versionadded:: 1.6
    """

    def __init__(self):
        self._system_host_keys = HostKeys()
        self._host_keys = HostKeys()
        self._host_keys_filename = None
        self._log_channel = None
        self._policy = RejectPolicy()
        self._transport = None
        self._security_options = None
        self._agent = None

    def get_security_options(self):
        """
        Return a `.SecurityOptions` object which can be used to tweak the authentication
        and encryption algorithms this client will permit (for encryption, digest/hash
        operations, public keys, and key exchanges) and the order of preference for them.
        """
        if self._security_options is None:
            # create a shadow Transport, copy the options to the real Transport later
            self._security_options = SecurityOptions(Transport(socket.socket()))

        return self._security_options

    def load_system_host_keys(self, filename=None):
        """
        Load host keys from a system (read-only) file.  Host keys read with
        this method will not be saved back by `save_host_keys`.

        This method can be called multiple times.  Each new set of host keys
        will be merged with the existing set (new replacing old if there are
        conflicts).

        If ``filename`` is left as ``None``, an attempt will be made to read
        keys from the user's local "known hosts" file, as used by OpenSSH,
        and no exception will be raised if the file can't be read.  This is
        probably only useful on posix.

        :param str filename: the filename to read, or ``None``

        :raises: ``IOError`` --
            if a filename was provided and the file could not be read
        """
        if filename is None:
            # try the user's .ssh key file, and mask exceptions
            filename = os.path.expanduser('~/.ssh/known_hosts')
            try:
                self._system_host_keys.load(filename)
            except IOError:
                pass
            return
        self._system_host_keys.load(filename)

    def load_host_keys(self, filename):
        """
        Load host keys from a local host-key file.  Host keys read with this
        method will be checked after keys loaded via `load_system_host_keys`,
        but will be saved back by `save_host_keys` (so they can be modified).
        The missing host key policy `.AutoAddPolicy` adds keys to this set and
        saves them, when connecting to a previously-unknown server.

        This method can be called multiple times.  Each new set of host keys
        will be merged with the existing set (new replacing old if there are
        conflicts).  When automatically saving, the last hostname is used.

        :param str filename: the filename to read

        :raises: ``IOError`` -- if the filename could not be read
        """
        self._host_keys_filename = filename
        self._host_keys.load(filename)

    def save_host_keys(self, filename):
        """
        Save the host keys back to a file.  Only the host keys loaded with
        `load_host_keys` (plus any added directly) will be saved -- not any
        host keys loaded with `load_system_host_keys`.

        :param str filename: the filename to save to

        :raises: ``IOError`` -- if the file could not be written
        """

        # update local host keys from file (in case other SSH clients
        # have written to the known_hosts file meanwhile.
        if self._host_keys_filename is not None:
            self.load_host_keys(self._host_keys_filename)

        with open(filename, 'w') as f:
            for hostname, keys in self._host_keys.items():
                for keytype, key in keys.items():
                    f.write('{} {} {}\n'.format(
                        hostname, keytype, key.get_base64()
                    ))

    def get_host_keys(self):
        """
        Get the local `.HostKeys` object.  This can be used to examine the
        local host keys or change them.

        :return: the local host keys as a `.HostKeys` object.
        """
        return self._host_keys

    def set_log_channel(self, name):
        """
        Set the channel for logging.  The default is ``"paramiko.transport"``
        but it can be set to anything you want.

        :param str name: new channel name for logging
        """
        self._log_channel = name

    def set_missing_host_key_policy(self, policy):
        """
        Set policy to use when connecting to servers without a known host key.

        Specifically:

        * A **policy** is a "policy class" (or instance thereof), namely some
          subclass of `.MissingHostKeyPolicy` such as `.RejectPolicy` (the
          default), `.AutoAddPolicy`, `.WarningPolicy`, or a user-created
          subclass.
        * A host key is **known** when it appears in the client object's cached
          host keys structures (those manipulated by `load_system_host_keys`
          and/or `load_host_keys`).

        :param .MissingHostKeyPolicy policy:
            the policy to use when receiving a host key from a
            previously-unknown server
        """
        if inspect.isclass(policy):
            policy = policy()
        self._policy = policy

    def connect(
        self,
        hostname,
        port=SSH_PORT,
        username=None,
        password=None,
        pkey=None,
        key_filename=None,
        timeout=None,
        allow_agent=True,
        look_for_keys=True,
        compress=False,
        sock=None,
        gss_auth=False,
        gss_kex=False,
        gss_deleg_creds=True,
        gss_host=None,
        banner_timeout=None,
        auth_timeout=None,
        gss_trust_dns=True,
        passphrase=None,
        handshake_timeout=None,
    ):
        """
        Connect to an SSH server and authenticate to it.  The server's host key
        is checked against the system host keys (see `load_system_host_keys`)
        and any local host keys (`load_host_keys`).  If the server's hostname
        is not found in either set of host keys, the missing host key policy
        is used (see `set_missing_host_key_policy`).  The default policy is
        to reject the key and raise an `.SSHException`.

        Authentication is attempted in the following order of priority:

            - The ``pkey`` or ``key_filename`` passed in (if any)

              - ``key_filename`` may contain OpenSSH public certificate paths
                as well as regular private-key paths; when files ending in
                ``-cert.pub`` are found, they are assumed to match a private
                key, and both components will be loaded. (The private key
                itself does *not* need to be listed in ``key_filename`` for
                this to occur - *just* the certificate.)

            - Any key we can find through an SSH agent
            - Any "id_rsa", "id_dsa", "id_ecdsa", or "id_ed25519" key
              discoverable in ``~/.ssh/``

              - When OpenSSH-style public certificates exist that match an
                existing such private key (so e.g. one has ``id_rsa`` and
                ``id_rsa-cert.pub``) the certificate will be loaded alongside
                the private key and used for authentication.

            - Plain username/password auth, if a password was given

        If a private key requires a password to unlock it, and a password is
        passed in, that password will be used to attempt to unlock the key.

        Note that the following parameters are documented in a different
        (more logical) order than they have in the function signature.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to
        :param str username:
            the username to authenticate as (defaults to the current local username)
        :param str password:
            Used for password authentication; is also used for private key
            decryption if ``passphrase`` is not given.
        :param str passphrase:
            Used for decrypting private key files
        :param .PKey pkey:
            an optional private key (object) to use for authentication
        :param str key_filename:
            the filename, or list of filenames, of optional private key(s)
            and/or certs to try for authentication
        :param bool look_for_keys:
            set to False to disable searching for discoverable private key files in ``~/.ssh/``
        :param bool allow_agent:
            set to False to disable connecting to the SSH agent
        :param float timeout:
            an optional timeout (in seconds) for the overall SSH session
            negotiation (also applies to the TCP connection)
        :param float banner_timeout:
            override default timeout (in seconds) to wait for the SSH banner
            to be presented
        :param float handshake_timeout:
            override default timeout (in seconds) to wait for the SSH handshake
            to finish after SSH banner exchange
        :param float auth_timeout:
            override default timeout (in seconds) to wait for an authentication response
        :param bool compress:
            enable deflate/gzip SSH transport compression
        :param socket sock:
            an open socket or socket-like object (such as a `.Channel`) to use
            for communication to the target host
        :param bool gss_auth:
            Use GSS-API authentication
        :param bool gss_kex:
            Perform GSS-API Key Exchange and user authentication
        :param bool gss_deleg_creds:
            Whether to delegate GSS-API client credentials (default ``True``)
        :param str gss_host:
            The targets name in the kerberos database. default: hostname
        :param bool gss_trust_dns:
            Indicates whether or not the DNS is trusted to securely
            canonicalize the name of the host being connected to (default ``True``)

        :raises: `.BadHostKeyException` -- if the server's host key could not be verified
        :raises: `.AuthenticationException` -- if authentication failed
        :raises: `.SSHException` -- if there was some other error establishing an SSH session
        :raises: `socket.error` -- if a socket error occurred while connecting

        .. versionchanged:: 1.15
            Added the ``banner_timeout``, ``gss_auth``, ``gss_kex``,
            ``gss_deleg_creds`` and ``gss_host`` arguments.
        .. versionchanged:: 2.2
            Added the ``auth_timeout`` argument.
        .. versionchanged:: 2.3
            Added the ``gss_trust_dns`` argument.
        .. versionchanged:: 2.4
            Added the ``passphrase`` argument.
        .. versionchanged:: 2.9
            Added the ``handshake_timeout`` argument.
        """
        if not sock:
            sock = retry_on_signal(
                lambda: socket.create_connection((hostname, port), timeout)
            )

        t = self._transport = Transport(
            sock, gss_kex=gss_kex, gss_deleg_creds=gss_deleg_creds
        )

        if self._security_options is not None:
            t_opts             = t.get_security_options()  # noqa: E221
            c_opts             = self._security_options    # noqa: E221
            t_opts.compression = c_opts.compression        # noqa: E221
            t_opts.key_types   = c_opts.key_types          # noqa: E221
            t_opts.ciphers     = c_opts.ciphers            # noqa: E221
            t_opts.digests     = c_opts.digests            # noqa: E221
            t_opts.kex         = c_opts.kex                # noqa: E221

        t.use_compression(compress=compress)
        t.set_gss_host(
            # t.hostname may be None, but GSS-API requires a target name.
            # Therefore use hostname as fallback.
            gss_host=gss_host or hostname,
            trust_dns=gss_trust_dns,
            gssapi_requested=gss_auth or gss_kex,
        )
        if self._log_channel is not None:
            t.set_log_channel(self._log_channel)
        if banner_timeout is not None:
            t.banner_timeout = banner_timeout
        if handshake_timeout is not None:
            t.handshake_timeout = handshake_timeout
        if auth_timeout is not None:
            t.auth_timeout = auth_timeout

        if port == SSH_PORT:
            server_hostkey_name = hostname
        else:
            server_hostkey_name = "[{}]:{}".format(hostname, port)
        our_server_keys = None

        our_server_keys = self._system_host_keys.get(server_hostkey_name)
        if our_server_keys is None:
            our_server_keys = self._host_keys.get(server_hostkey_name)
        if our_server_keys is not None:
            keytype = our_server_keys.keys()[0]
            sec_opts = t.get_security_options()
            other_types = [x for x in sec_opts.key_types if x != keytype]
            sec_opts.key_types = [keytype] + other_types

        t.start_client(timeout=timeout)

        # If GSS-API Key Exchange is performed we are not required to check the
        # host key, because the host is authenticated via GSS-API / SSPI as
        # well as our client.
        if not self._transport.gss_kex_used:
            server_key = t.get_remote_server_key()
            if our_server_keys is None:
                # will raise exception if the key is rejected
                self._policy.missing_host_key(
                    self, server_hostkey_name, server_key
                )
            else:
                our_key = our_server_keys.get(server_key.get_name())
                if our_key != server_key:
                    if our_key is None:
                        our_key = list(our_server_keys.values())[0]
                    raise BadHostKeyException(hostname, server_key, our_key)

        if username is None:
            username = getpass.getuser()

        if key_filename is None:
            key_filenames = []
        elif isinstance(key_filename, string_types):
            key_filenames = [key_filename]
        else:
            key_filenames = key_filename

        self._auth(
            username, password, pkey, key_filenames, allow_agent,
            look_for_keys, gss_auth, gss_kex, gss_deleg_creds, t.gss_host,
            passphrase,
        )

    def close(self):
        """
        Close this SSHClient and its underlying `.Transport`.

        .. warning::
            Failure to do this may, in some situations, cause your Python
            interpreter to hang at shutdown (often due to race conditions).
            It's good practice to `close` your client objects anytime you're
            done using them, instead of relying on garbage collection.
        """
        self._security_options = None  # has reference to "shadow Transport"

        if self._transport is not None:
            self._transport.close()
            self._transport = None

        if self._agent is not None:
            self._agent.close()
            self._agent = None

    def exec_command(
        self,
        command,
        bufsize=-1,
        timeout=None,
        get_pty=False,
        environment=None,
        open_timeout=None,
    ):
        """
        Execute a command on the SSH server.  A new `.Channel` is opened and
        the requested command is executed.  The command's input and output
        streams are returned as Python ``file``-like objects representing
        stdin, stdout, and stderr.

        :param str command: the command to execute
        :param int bufsize:
            interpreted the same way as by the built-in ``file()`` function in
            Python
        :param int timeout:
            set command's channel timeout. See `.Channel.settimeout`
        :param bool get_pty:
            Request a pseudo-terminal from the server (default ``False``).
            See `.Channel.get_pty`
        :param dict environment:
            a dict of shell environment variables, to be merged into the
            default environment that the remote command executes within.
        :param int open_timeout:
            timeout (in seconds) to open a new channel. If None, value of `timeout` is used.

            .. warning::
                Servers may silently reject some environment variables; see the
                warning in `.Channel.set_environment_variable` for details.

        :return:
            the stdin, stdout, and stderr of the executing command, as a
            3-tuple

        :raises: `.SSHException` -- if the server fails to execute the command

        .. versionchanged:: 1.10
            Added the ``get_pty`` kwarg.
        """
        if open_timeout is None:
            open_timeout = timeout
        chan = self._transport.open_session(timeout=open_timeout)
        if get_pty:
            chan.get_pty()
        chan.settimeout(timeout)
        if environment:
            chan.update_environment(environment)
        chan.exec_command(command)
        stdin = chan.makefile_stdin('wb', bufsize)
        stdout = chan.makefile('r', bufsize)
        stderr = chan.makefile_stderr('r', bufsize)
        return stdin, stdout, stderr

    def invoke_shell(self, term='vt100', width=80, height=24, width_pixels=0,
                     height_pixels=0, environment=None):
        """
        Start an interactive shell session on the SSH server.  A new `.Channel`
        is opened and connected to a pseudo-terminal using the requested
        terminal type and size.

        :param str term:
            the terminal type to emulate (for example, ``"vt100"``)
        :param int width: the width (in characters) of the terminal window
        :param int height: the height (in characters) of the terminal window
        :param int width_pixels: the width (in pixels) of the terminal window
        :param int height_pixels: the height (in pixels) of the terminal window
        :param dict environment: the command's environment
        :return: a new `.Channel` connected to the remote shell

        :raises: `.SSHException` -- if the server fails to invoke a shell
        """
        chan = self._transport.open_session()
        if environment:
            chan.update_environment(environment)
        chan.get_pty(term, width, height, width_pixels, height_pixels)
        chan.invoke_shell()
        return chan

    def open_sftp(self):
        """
        Open an SFTP session on the SSH server.

        :return: a new `.SFTPClient` session object
        """
        return self._transport.open_sftp_client()

    def get_transport(self):
        """
        Return the underlying `.Transport` object for this SSH connection.
        This can be used to perform lower-level tasks, like opening specific
        kinds of channels.

        :return: the `.Transport` for this connection
        """
        return self._transport

    def _key_from_filepath(self, filename, klass=None, password=None):
        """
        Attempt to derive a `.PKey` from given string path ``filename``:

        - If ``filename`` appears to be a cert, the matching private key is
          loaded.
        - Otherwise, the filename is assumed to be a private key, and the
          matching public cert will be loaded if it exists.
        """
        cert_suffix = '-cert.pub'
        # Assume privkey, not cert, by default
        if filename.endswith(cert_suffix):
            key_path = filename[:-len(cert_suffix)]
            cert_path = filename
        else:
            key_path = filename
            cert_path = filename + cert_suffix
        # Blindly try the key path; if no private key, nothing will work.
        if klass:
            key = klass.from_private_key_file(key_path, password)
        else:
            key = load_private_key_file(key_path, password)
        self._log(DEBUG, "Trying discovered key %s in %s" % (
            key.get_fingerprint_sha256_b64(), key_path,
        ))
        # Attempt to load cert if it exists.
        if os.path.isfile(cert_path):
            key.load_certificate(cert_path)
            self._log(DEBUG, "Adding public certificate {}".format(cert_path))
        return key

    def _auth(
        self, username, password, pkey, key_filenames, allow_agent,
        look_for_keys, gss_auth, gss_kex, gss_deleg_creds, gss_host,
        passphrase,
    ):
        """
        Try, in order:

            - The key(s) passed in, if one was passed in.
            - Any key we can find through an SSH agent (if allowed).
            - Any "id_rsa", "id_dsa" or "id_ecdsa" key discoverable in ~/.ssh/
              (if allowed).
            - Plain username/password auth, if a password was given.

        (The password might be needed to unlock a private key [if 'passphrase'
        isn't also given], or for two-factor authentication [for which it is
        required].)
        """
        saved_exception = None
        two_factor = False
        allowed_types = set()
        two_factor_types = {'keyboard-interactive', 'password'}
        if passphrase is None and password is not None:
            passphrase = password

        # If GSS-API support and GSS-PI Key Exchange was performed, we attempt
        # authentication with gssapi-keyex.
        if gss_kex and self._transport.gss_kex_used:
            try:
                self._transport.auth_gssapi_keyex(username)
                return
            except Exception as e:
                saved_exception = e

        # Try GSS-API authentication (gssapi-with-mic) only if GSS-API Key
        # Exchange is not performed, because if we use GSS-API for the key
        # exchange, there is already a fully established GSS-API context, so
        # why should we do that again?
        if gss_auth:
            try:
                return self._transport.auth_gssapi_with_mic(
                    username, gss_host, gss_deleg_creds,
                )
            except Exception as e:
                saved_exception = e

        # detect what authentication methods the server supports
        # mirrors what openssh client does
        try:
            self._transport.auth_none(username)
        except BadAuthenticationType as e:
            allowed_types = set(e.allowed_types)
        else:
            return  # successful login with no auth

        # some servers do not return allowed auth methods
        if not allowed_types:
            allowed_types = {'password', 'publickey'}

        if pkey is not None and 'publickey' in allowed_types:
            try:
                self._log(DEBUG, "Trying SSH key %s" % pkey.get_fingerprint_sha256_b64())
                allowed_types = set(
                    self._transport.auth_publickey(username, pkey))
                two_factor = (allowed_types & two_factor_types)
                if not two_factor:
                    return
            except SSHException as e:
                saved_exception = e

        if not two_factor and 'publickey' in allowed_types:
            for key_filename in key_filenames:
                try:
                    key = self._key_from_filepath(key_filename, password=passphrase)

                    allowed_types = set(self._transport.auth_publickey(username, key))
                    two_factor = (allowed_types & two_factor_types)
                    if not two_factor:
                        return
                    break
                except SSHException as e:
                    saved_exception = e

        if allow_agent and not two_factor and 'publickey' in allowed_types:
            if self._agent is None:
                self._agent = Agent()

            for key in self._agent.get_keys():
                try:
                    self._log(DEBUG, "Trying SSH agent key %s" % key.get_fingerprint_sha256_b64())
                    allowed_types = set(
                        self._transport.auth_publickey(username, key))
                    two_factor = (allowed_types & two_factor_types)
                    if not two_factor:
                        return
                    break
                except SSHException as e:
                    saved_exception = e

        if look_for_keys and not two_factor and 'publickey' in allowed_types:
            keyfiles = []
            for keytype, name in [
                (RSAKey, "rsa"),
                (DSSKey, "dsa"),
                (ECDSAKey, "ecdsa"),
                (Ed25519Key, "ed25519"),
            ]:
                # ~/ssh/ is for windows
                for directory in [".ssh", "ssh"]:
                    full_path = os.path.expanduser(
                        "~/{}/id_{}".format(directory, name)
                    )
                    if os.path.isfile(full_path):
                        # TODO: only do this append if below did not run
                        keyfiles.append((keytype, full_path))
                        if os.path.isfile(full_path + '-cert.pub'):
                            keyfiles.append((keytype, full_path + '-cert.pub'))

            for pkey_class, filename in keyfiles:
                try:
                    key = self._key_from_filepath(
                        filename, pkey_class, passphrase,
                    )
                    allowed_types = set(
                        self._transport.auth_publickey(username, key))
                    two_factor = (allowed_types & two_factor_types)
                    if not two_factor:
                        return
                    break
                except (SSHException, IOError) as e:
                    saved_exception = e

        # possible two_factor second factors
        # (allowed_types could have been updated, only if two_factor)

        if password is not None and 'password' in allowed_types:
            try:
                self._log(DEBUG, 'Trying password')
                allowed_types = set(
                    self._transport.auth_password(username, password, fallback=False)
                )
                if 'keyboard-interactive' not in allowed_types:
                    return
            except SSHException as e:
                saved_exception = e

        elif password is not None and 'keyboard-interactive' in allowed_types:
            try:
                self._log(DEBUG, 'Trying password for keyboard-interactive')
                allowed_types = set(
                    self._transport.auth_interactive_static(username, password)
                )
                if 'keyboard-interactive' not in allowed_types:
                    return
            except SSHException as e:
                saved_exception = e

        if 'keyboard-interactive' in allowed_types:
            try:
                self._log(DEBUG, 'Trying interactive auth')
                self._transport.auth_interactive_dumb(username)
                return
            except SSHException as e:
                saved_exception = e

        # if we got an auth-failed exception earlier, re-raise it
        if saved_exception is not None:
            raise saved_exception
        raise SSHException('No authentication methods available')

    def _log(self, level, msg):
        self._transport._log(level, "%s", msg)


class MissingHostKeyPolicy (object):
    """
    Interface for defining the policy that `.SSHClient` should use when the
    SSH server's hostname is not in either the system host keys or the
    application's keys.  Pre-made classes implement policies for automatically
    adding the key to the application's `.HostKeys` object (`.AutoAddPolicy`),
    and for automatically rejecting the key (`.RejectPolicy`).

    This function may be used to ask the user to verify the key, for example.
    """

    def missing_host_key(self, client, hostname, key):
        """
        Called when an `.SSHClient` receives a server key for a server that
        isn't in either the system or local `.HostKeys` object.  To accept
        the key, simply return.  To reject, raised an exception (which will
        be passed to the calling application).
        """
        pass


class AutoAddPolicy (MissingHostKeyPolicy):
    """
    Policy for automatically adding the hostname and new host key to the
    local `.HostKeys` object, and saving it.  This is used by `.SSHClient`.
    """

    def missing_host_key(self, client, hostname, key):
        client._host_keys.add(hostname, key.get_name(), key)
        if client._host_keys_filename is not None:
            client.save_host_keys(client._host_keys_filename)
        client._log(DEBUG, "Adding %s host key for %s: %s" % (
            key.get_name(), hostname, key.get_fingerprint_sha256_b64(),
        ))


class RejectPolicy (MissingHostKeyPolicy):
    """
    Policy for automatically rejecting the unknown hostname & key.  This is
    used by `.SSHClient`.
    """

    def missing_host_key(self, client, hostname, key):
        client._log(DEBUG, "Rejecting %s host key for %s: %s" % (
            key.get_name(), hostname, key.get_fingerprint_sha256_b64,
        ))
        raise SSHException(
            'Server {!r} not found in known_hosts'.format(hostname)
        )


class WarningPolicy (MissingHostKeyPolicy):
    """
    Policy for logging a Python-style warning for an unknown host key, but
    accepting it. This is used by `.SSHClient`.
    """
    def missing_host_key(self, client, hostname, key):
        warnings.warn("Unknown %s host key for %s: %s" % (
            key.get_name(), hostname, key.get_fingerprint_sha256_b64(),
        ))
