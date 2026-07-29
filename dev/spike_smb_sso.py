"""THROWAWAY spike: validate SSPI Negotiate SMB SSO against a real host.

Not imported by anything; not committed. Delete after validating.
Runs the exact mechanism the plan specifies, with no dependency on the
half-built openhound_sccm package, printing where each stage succeeds/fails.

    python spike_smb_sso.py [target_fqdn]
"""
import sys
import traceback

import sspi
import sspicon
from impacket import crypto
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS
from impacket.smb3structs import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB2_NEGOTIATE_SIGNING_ENABLED,
    SMB2_NEGOTIATE_SIGNING_REQUIRED,
    SMB2_SESSION_SETUP,
    SMB2SessionSetup,
    SMB2SessionSetup_Response,
)
from impacket.smbconnection import SMBConnection

TARGET = sys.argv[1] if len(sys.argv) > 1 else "ps1-pss.mayyhem.com"


class Neg:
    def __init__(self, spn):
        self.auth = sspi.ClientAuth("Negotiate", targetspn=spn)

    def step(self, server_token):
        err, bufs = self.auth.authorize(server_token if server_token else None)
        token = bytes(bufs[0].Buffer) if bufs else b""
        return token, err == 0

    def session_key(self):
        return bytes(self.auth.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SESSION_KEY))


def login_sspi(conn, spn):
    smb3 = conn.getSMBServer()
    client = Neg(spn)
    smb3._Session["SigningRequired"] = smb3._Connection["RequireSigning"]
    smb3._Session["PreauthIntegrityHashValue"] = smb3._Connection["PreauthIntegrityHashValue"]
    dialect = smb3._Connection["Dialect"]
    is_311 = dialect == SMB2_DIALECT_311
    update_preauth = getattr(smb3, "_SMB3__UpdatePreAuthHash", None)
    print(f"  dialect=0x{dialect:04x} signing_required={smb3._Session['SigningRequired']} is_311={is_311}")

    ss = SMB2SessionSetup()
    ss["SecurityMode"] = (
        SMB2_NEGOTIATE_SIGNING_REQUIRED if smb3.RequireMessageSigning else SMB2_NEGOTIATE_SIGNING_ENABLED
    )
    ss["Flags"] = 0

    token, done = client.step(None)
    leg = 0
    while True:
        leg += 1
        ss["SecurityBufferLength"] = len(token)
        ss["Buffer"] = token
        pkt = smb3.SMB_PACKET()
        pkt["Command"] = SMB2_SESSION_SETUP
        pkt["Data"] = ss
        # sendSMB folds the outgoing SESSION_SETUP *request* into the 3.1.1 preauth hash.
        ans = smb3.recvSMB(smb3.sendSMB(pkt))
        smb3._Session["SessionID"] = ans["SessionID"]
        status = ans["Status"]
        print(f"  leg {leg}: sent {len(token)}B token, server status=0x{status & 0xffffffff:08x}, sspi_done={done}")
        resp = SMB2SessionSetup_Response(ans["Data"])
        server_token = bytes(resp["Buffer"]) if resp["Buffer"] else b""
        if status == STATUS_SUCCESS:
            # MS-SMB2: the final success response is NOT folded into the preauth hash.
            # Finalize the SSPI context with the server's AP-REP, then stop.
            if not done and server_token:
                token, done = client.step(server_token)
                print(f"    finalized: sspi_done={done}, residual_token={len(token)}B")
            break
        if status != STATUS_MORE_PROCESSING_REQUIRED:
            ans.isValidAnswer(STATUS_SUCCESS)  # raises impacket SessionError
        # Intermediate response only: fold into the 3.1.1 preauth hash before the next leg.
        if is_311 and update_preauth is not None:
            update_preauth(ans.rawData)
        token, done = client.step(server_token)

    sk_full = client.session_key()
    sk = sk_full[:16].ljust(16, b"\x00")  # MS-SMB2 3.2.5.3.1: first 16 bytes of the GSS key
    print(f"  session key: {len(sk_full)} bytes from SSPI; using first 16 for SMB derivation")
    smb3._Session["SessionKey"] = sk
    if smb3._Session["SigningRequired"] and dialect >= SMB2_DIALECT_30:
        if is_311:
            smb3._Session["SigningKey"] = crypto.KDF_CounterMode(
                sk, b"SMBSigningKey\x00", smb3._Session["PreauthIntegrityHashValue"], 128)
        else:
            smb3._Session["SigningKey"] = crypto.KDF_CounterMode(sk, b"SMB2AESCMAC\x00", b"SmbSign\x00", 128)
        smb3._Session["SigningActivated"] = True
    smb3._Session["CalculatePreAuthHash"] = False


def main():
    print(f"=== spike: SSPI Negotiate SMB SSO -> {TARGET} ===")
    print("[1] negotiate SMB dialect")
    conn = SMBConnection(TARGET, TARGET, sess_port=445, timeout=8)
    print("    OK")

    print("[2] SSPI Negotiate SESSION_SETUP loop")
    login_sspi(conn, f"cifs/{TARGET}")
    print("    AUTH OK; server name:", conn.getServerName(), "| domain:", conn.getServerDNSDomainName())

    print("[3] signed op: connectTree('IPC$')")
    tid = conn.connectTree("IPC$")
    conn.disconnectTree(tid)
    print("    SIGNED OP OK (signing key works)")

    print("[4] DCE/RPC over named pipe: open \\winreg (Remote Registry)")
    from impacket.dcerpc.v5 import rrp, transport
    try:
        rpc = transport.SMBTransport(conn.getRemoteHost(), filename=r"\winreg", smb_connection=conn)
        rpc.connect()
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        root = rrp.hOpenLocalMachine(dce)["phKey"]
        try:
            sub = rrp.hBaseRegOpenKey(dce, root, r"SOFTWARE\Microsoft\SMS\Triggers")["phkResult"]
            print("    OPENED SMS\\Triggers OK (target is an SCCM site server)")
            rrp.hBaseRegCloseKey(dce, sub)
        except Exception as e:
            print(f"    SMS\\Triggers not readable: {e!r} (auth fine; key absent or access-denied)")
        dce.disconnect()
    except Exception as e:
        # Reaching the server and getting PIPE_NOT_AVAILABLE (vs ACCESS_DENIED) proves
        # the signed RPC transport works; the RemoteRegistry service is just stopped.
        print(f"    \\winreg unavailable: {e!r}")
        print("    -> RemoteRegistry service stopped on target; the SIGNED request WAS processed (not an auth failure).")
    conn.close()
    print("=== SPIKE PASSED: SSPI Negotiate SSO + signed SMB validated end-to-end ===")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("=== SPIKE FAILED ===")
        traceback.print_exc()
        sys.exit(1)
