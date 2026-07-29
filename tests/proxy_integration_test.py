"""Offline integration spike: do ldap3 / requests / impacket funnel through the
SOCKS5 interception? Drives each real library at an internal name via a local
recording SOCKS5 stub and asserts the CONNECT (with the hostname) reached it.
No live target or real proxy needed."""
import socket
import struct
import threading

import pytest

from openhound_collector_common.proxy import ProxyConfig, socks_proxy_installed


class RecordingSocks5:
    """A local SOCKS5 CONNECT server that records each requested target."""

    def __init__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self.targets = []
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(3)
            greet = conn.recv(2)
            if len(greet) < 2:
                return
            conn.recv(greet[1])  # methods
            conn.sendall(bytes([0x05, 0x00]))  # no-auth
            head = conn.recv(4)
            if len(head) < 4:
                return
            atyp = head[3]
            if atyp == 0x01:
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 0x03:
                host = conn.recv(conn.recv(1)[0]).decode()
            else:
                conn.recv(16)
                host = "<ipv6>"
            port = struct.unpack("!H", conn.recv(2))[0]
            self.targets.append((host, port))
            conn.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            try:
                conn.recv(64)  # let the client send app bytes, then drop
            except OSError:
                pass
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _drive(stub, fn):
    with socks_proxy_installed(ProxyConfig(host=stub.host, port=stub.port)):
        try:
            fn()
        except Exception:
            pass  # app-level failure AFTER connect is expected (stub isn't a real server)


@pytest.fixture
def stub():
    s = RecordingSocks5()
    yield s
    s.close()


def test_ldap3_funnels_through_proxy(stub):
    def go():
        import ldap3
        server = ldap3.Server("dc.internal.invalid", port=389, connect_timeout=3)
        conn = ldap3.Connection(server, receive_timeout=3)
        conn.open()  # opens the socket; that's all we need to observe
    _drive(stub, go)
    assert ("dc.internal.invalid", 389) in stub.targets


def test_requests_funnels_through_proxy(stub):
    def go():
        import requests
        requests.get("http://mp.internal.invalid/", timeout=3)
    _drive(stub, go)
    assert ("mp.internal.invalid", 80) in stub.targets


def test_impacket_smb_funnels_through_proxy(stub):
    def go():
        from impacket.smbconnection import SMBConnection
        SMBConnection("smb.internal.invalid", "smb.internal.invalid", sess_port=445, timeout=3)
    _drive(stub, go)
    assert ("smb.internal.invalid", 445) in stub.targets
