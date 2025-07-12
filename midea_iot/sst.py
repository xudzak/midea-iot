# pyright: reportGeneralTypeIssues=false, reportInvalidTypeForm=false
import enum
import hashlib
import secrets

from caterpillar.shortcuts import bitfield, BigEndian, opt, struct, this
from caterpillar.model import unpack, pack
from caterpillar.fields import uint8, uint16, padding
from caterpillar.py import EnumFactory, Bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# This protocol is referenced as "v3 (8370) protocol" by
# nbogojevic in midea-beautiful-air. However, the original
# name seems to be related to the SST or secsmarts, which
# is available in the Android SDK.
#
# The SST protocol defines two different packet structures
# on UDP and TCP, both starting with the header mark: 8370

SST_HEADER_MARK = b"\x83\x70"
"""Header magic for the SST protocol"""


# The actual packet ships with different commands. By default,
# discovery messages and heartbeat messages don'T require extra
# encryption
class SstCommand(enum.IntEnum):
    """Describes different SST command types"""

    # key agreement request
    REQUEST = 0
    # Response: TODO
    # - has something to do with the key agreement
    RESPONSE = 1
    # TcpData:
    # - TCP data encrypted using shared/agreed key
    TCP_DATA = 3
    # Not seen
    CIPHERSND = 6
    # Unencrypted frame - mostly used for UDP messages
    PLAINSND = 15


# Extra struct:
@bitfield
class SstType:
    """Stores information about the packet type."""

    # fmt: off
    # The SDK includes a special convention to include
    # a constant value before defining the actual type
    reserved : uint8                        = 32

    # this field is originally called 'addNum' - It stores
    # the amount of padding bytes added to the decrypted
    # data.
    pad_len  :  4                           = 0

    # The action command of this SST packet
    command  : (4, EnumFactory(SstCommand)) = SstCommand.PLAINSND
    # fmt: on


@struct(order=BigEndian, options=[opt.S_DISCARD_UNNAMED])
class SstPacketBase:
    """SST Packet (Base)"""

    # fmt: off
    # The header MUST always start with the two magic bytes
    magic  : SST_HEADER_MARK

    # Stores the length of this frame's payload. For UDP datagrams,
    # this value also includes the length of the UDP-Id.
    length : uint16                 = 0
    type   : SstType

    # The next two bytes seem to be reserved - they are never used
    _      : padding[2]

    # both packet types (TCP and UDP) will define the payload field
    # fmt: on

    def build(self):
        return pack(self)


@struct
class SstFrame(SstPacketBase):
    """SST Packet (TCP)"""

    # fmt: off
    # Stores the packet data formatted according to the command type
    payload: Bytes(this.length)         = bytes()
    # fmt: on

    def set_payload(self, data: bytes):
        """Applies a new payload to this packet (updates length)"""
        self.payload = data
        self.length = len(self.payload)

    def is_error(self) -> bool:
        return self.payload == b"ERROR"

    @staticmethod
    def from_bytes(data: bytes):
        return unpack(SstFrame, data)


@struct
class SstDatagram(SstPacketBase):
    """SST Packet (UDP)"""

    # fmt: off
    # Stores the packet data formatted according to the command type
    payload: Bytes(this.length - 16)    = bytes()

    # UDP-Key ID:
    # Some identifier for the backend to grant access tokens. It can
    # be calculated using the device-id:
    #
    #   devIDHash = SHA256(deviceId.hex())
    #   udpKeyId  = XOR(devIdHash[:16], devIdHash[16:32])
    udp_id : Bytes(16)                  = bytes(16)
    # fmt: on

    def set_payload(self, data: bytes):
        """Applies a new payload to this packet (updates length)"""
        self.payload = data
        self.length = len(data) + 16

    @staticmethod
    def from_bytes(data: bytes):
        """Parses the given buffer into a SST datagram"""
        return unpack(SstDatagram, data)


class SstException(Exception):
    # base exception for all SST related errors
    pass


class SstKeyAgreementFail(SstException):
    # Thrown when errors occur during key exchange
    pass


class SstComputeHashFail(SstException):
    # Used for hash verification, see:
    #   - ka_get_devkey
    pass


def udp_keyid_from_deviceid(device_id_hex: str) -> bytes:
    """Converts a given device ID (hex string) into a UDP key Id"""

    # Format of the UDP-KEY-ID is built from the device ID according to
    # the old android SDK:
    #   dhash      := SHA256(deviceId)
    #   UDP-KEY-ID := XOR(dhash[:16], dhash[16:32])
    dev_id_hash = hashlib.sha256(bytes.fromhex(device_id_hex)).digest()
    data, key = dev_id_hash[:16], dev_id_hash[16:32]
    return bytes([x_data ^ x_key for (x_data, x_key) in zip(data, key)])


# Key Agreement (based on old SDK):
#   - Device detected by broadcast
#   + CLOUD:
#       - Acquire UDP-KEY-ID and send it to the CLOUD to receive the following
#         attributes:
#           + token
#           + k1 (decrypt key)
#       - Send a REQUEST message to the device containing the token
#   + LOCAL:
#       - Acquire UDP-KEY-ID and assign it with the device
#       - Generate a new key 'k1':
#           k1 := RANDOM[16]
#       - Compute the encryption key (R3):
#           R3 := SHA256(WIFI_SSID + WIFI_PWD + DEVICE_MAC)
#       - Encrypt 'k1' using the computed 'R3' secret key:
#           KEY   := R3
#           PLAIN := k1
#           IV    := EMPTY_IV
#           ENC   := AES/CBC/NoPadding(PLAIN, KEY, IV)
#       - Additionally, the hash of 'k1' is computed and added to the message:
#           hk1 := SHA256(k1)
#
#   - the returned packet contains the device key (used for pacekt encryption
#     within a session) encrypted using the agreement key:
#       KEY    := k1
#       ENC    := PAYLOAD[0..(LEN(ENC)-32)]
#       IV     := EMPTY_IV
#       PLAIN  := AES/CBC/NoPadding(ENC, KEY, IV)
#       devKey := PLAIN
#   - Additionally, the hash of the device key can be verified:
#       hDevKey := PAYLOAD[(LEN(ENC)-32)..]
#       assert hDevKey is SHA256(devKey)
#
# NOTE: the new SDK does not define any local key agreement tasks unless
# specific protocol versions are defined.


def get_r3(wifi_ssid: bytes, wifi_pwd: bytes, device_mac: bytes) -> bytes:
    """Calculates the shared secret key.

    Note that the device MAC MUST NOT contain any filler bytes.
    """
    return hashlib.sha256(wifi_ssid + wifi_pwd + device_mac).digest()


def get_new_k1():
    """Generates a new agreement key"""
    return secrets.token_bytes(16)


def ka_token_request(token: bytes) -> SstPacketBase:
    """(KeyAgreement) Builds a new agreement request using the given token (CLOUD)"""
    frame = SstFrame(type=SstType(command=SstCommand.REQUEST))
    frame.set_payload(token)
    return frame


def ka_udp_msg_request(k1: bytes, r3: bytes) -> SstDatagram:
    """(KeyAgreement) Builds a new agreement request (LOCAL, UDP)"""
    return ka_msg_request(SstDatagram, k1, r3)


def ka_tcp_msg_request(k1: bytes, r3: bytes) -> SstFrame:
    """(KeyAgreement) Builds a new agreement request (LOCAL, TCP)"""
    return ka_msg_request(SstFrame, k1, r3)


def ka_msg_request(
    model: type[SstFrame] | type[SstDatagram], k1: bytes, r3: bytes
) -> SstFrame | SstDatagram:
    """(KeyAgreement) Builds a new agreement request (LOCAL)"""

    # The request is encrypted using the current WIFI's SSID and
    # password as well as the mac address of the device. The secret
    # key will be used to encrypt the agreement key (k1) that encodes
    # the final UDP/TCP key.
    #
    #     KEY   := R3
    #     PLAIN := k1
    #     IV    := EMPTY_IV
    #     ENC   := AES/CBC/NoPadding(PLAIN, KEY, IV)
    #
    # The final payload consists of the encrypted XOR key (k1) and
    # its SHA256 hash:
    #
    #     DATA  := ENC + SHA256(k1)
    frame = model(type=SstType(command=SstCommand.REQUEST))
    cipher = Cipher(algorithms.AES(r3), modes.CBC(bytes(16)))
    encryptor = cipher.encryptor()

    enc = encryptor.update(k1) + encryptor.finalize()
    hk1 = hashlib.sha256(k1).digest()
    frame.set_payload(enc + hk1)
    return frame


def ka_get_devkey(packet: SstDatagram | SstFrame, k1: bytes) -> bytes:
    """(KeyAgreement) Extract device key from SST response

    Raises SstComputeHashFail if the embedded digest does not match the
    device key.
    """
    # assert packet.type.command == SstCommand.RESPONSE

    # The returned packet contains the device key encrypted using
    # the agreement key:
    #       KEY    := k1
    #       ENC    := PAYLOAD[0..(LEN(ENC)-32)]
    #       IV     := EMPTY_IV
    #       PLAIN  := AES/CBC/NoPadding(ENC, KEY, IV)
    #       devKey := PLAIN
    payload = packet.payload
    enc, h_sk = payload[:-32], payload[-32:]

    iv = bytes(16)  # always empty
    cipher = Cipher(algorithms.AES(k1), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain = decryptor.update(enc) + decryptor.finalize()

    #   - Additionally, the hash of the device key can be verified:
    #       hDevKey := PAYLOAD[(LEN(ENC)-32)..]
    #       assert hDevKey is SHA256(devKey)
    h_plain = hashlib.sha256(plain).digest()
    if h_plain != h_sk:
        raise SstComputeHashFail(f"Expected {h_sk.hex()} as digest, got {h_sk.hex()}")

    return plain
