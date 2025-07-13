# pyright: reportGeneralTypeIssues=false, reportInvalidTypeForm=false
import enum
import hashlib
import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms, aead
from cryptography.hazmat.primitives.padding import PKCS7

from caterpillar.shortcuts import bitfield, LittleEndian, struct
from caterpillar.model import unpack, pack
from caterpillar.fields import uint8, uint16, uint32
from caterpillar.py import EnumFactory, Bytes

from midea_iot.const import DEFAULT_KEY, DEFAULT_KEY_MD5

# Packets sent over Wifi to the appliance / device are using a specific
# protocol that comes with another special magic bytes mark: '5A5A'.
# Even though the packet / struct is named 'datagram', it will be sent
# over both channels, UDP and TCP.
#
# The current version of the protocol includes a new encryption type
# ('AES/CCM') compared to the initial Android SDK release.

WIFI_HEADER_MARK = b"\x5a\x5a"
"""Header magic for a Wifi datagram"""


# The 'payload' of each datagram depends on the message type. Most of
# these message types were defined only, but actually never used.
class WifiCommand(enum.IntEnum):
    # Each message type uses two bytes (originally int16, but changed
    # to unsigned integer).
    __struct__ = uint16

    CONFIGURE_WIFI_REQUEST = 0x70
    CONFIGURE_WIFI_RESPONSE = 0x8070
    DEVICE_BATCH_DATA_TRANSMIT = 0xD0
    DEVICE_BATCH_DATA_TRANSMIT_RESPONSE = 0x80D0
    DEVICE_BATCH_REPORT_SUBDEVICES = 0xD1
    DEVICE_BATCH_REPORT_SUBDEVICES_RESPONSE = 0x80D1
    DEVICE_BROADCAST = 0x7A
    DEVICE_BROADCAST_RESPONSE = 0x807A
    DEVICE_DATA_TRANSMIT = 0x20
    DEVICE_DATA_TRANSMIT_RESPONSE = 0x8020
    DEVICE_NEW_ENERGY_DATA_PUSH = 0xD7
    DEVICE_NEW_ENERGY_DATA_PUSH_RESPONE = 0x80D7
    DEVICE_NEW_ENERGY_DATA_TRANSMIT = 0xD6
    DEVICE_NEW_ENERGY_DATA_TRANSMIT_RESPONSE = 0x80D6
    DEVICE_NEW_ENERGY_SUBORDER_OPERATION = 0x1
    DEVICE_NEW_ENERGY_SUBORDER_QUERY = 0x3
    DEVICE_NEW_ENERGY_SUBORDER_QUERYALL = 0x4
    DEVICE_NEW_ENERGY_SUBORDER_SET = 0x2
    DEVICE_OBJECT_MODEL_DATA_TRANSMIT = 0xD4
    DEVICE_OBJECT_MODEL_DATA_TRANSMIT_RESPONSE = 0x80D4
    DEVICE_OBJECT_MODEL_STATE_REPORT = 0xD5
    DEVICE_OBJECT_MODEL_STATE_REPORT_RESPONSE = 0x80D5
    DEVICE_QUERY_LAST_ERRORCODE = 0x73
    DEVICE_QUERY_LAST_ERRORCODE_RESPONSE = 0x8073
    DEVICE_SEND_WIFIINFO = 0x72
    DEVICE_SEND_WIFIINFO_RESPONSE = 0x8072
    DEVICE_STATE_REPORT = 0x40
    DEVICE_STATE_REPORT_NEED_RESPONSE = 0x44
    DEVICE_STATE_REPORT_RESPONSE = 0x8044
    QUERY_COMBINATION_REQUEST = 0x74
    QUERY_COMBINATION_RESPONSE = 0x8074
    QUERY_ERROR_REQUEST = 0x71
    QUERY_ERROR_RESPONSE = 0x8071
    SEARCH_DEVICE_BROADCAST = 0x92
    SEARCH_DEVICE_BROADCAST_RESPONSE = 0x8092
    SEND_HEART_BEAT = 0x7B
    SEND_HEART_BEAT_RESPONSE = 0x807B
    SWITCH_WIFI_MODE = 0x81
    SWITCH_WIFI_MODE_RESPONSE = 0x8081
    WRITE_DEVICE_ID = 0x43
    WRITE_DEVICE_ID_RESPONSE = 0x8043
    WRITE_WIFI_INFO = 0x68
    WRITE_WIFI_INFO_RESPONSE = 0x8068
    GET_WIFI_FIRMWARE_VERSION_REQUEST = 0x87
    GET_WIFI_FIRMWARE_VERSION_RESPONSE = 0x8087
    REBOOT_WIFI_FIRMWARE_REQUEST = 0x82
    REBOOT_WIFI_FIRMWARE_RESPONSE = 0x8082
    TLS_CERT_REQUEST = 0x75
    TLS_CERT_RESPONSE = 0x8075
    TLS_CONTROL_REQUEST = 0x9
    TLS_CONTROL_RESPONSE = 0x8009
    UPGRADE_LICENSE_REQUEST = 0x89
    UPGRADE_LICENSE_RESPONSE = 0x8089
    UPGRADE_WIFI_FIRMWARE_REQUEST = 0x88
    UPGRADE_WIFI_FIRMWARE_RESPONSE = 0x8088


# The encryption type specifies when encryption mechanism should
# be applied to he actual payload of the Wifi datagram.
class EncryptType(enum.IntEnum):
    """Encryption mode to apply to the payload of a datagram"""

    NONE = 0
    """No encryption, just plaintext"""

    AES128 = 1
    """
    Standard AES128/ECB/PKCS7Padding encryption mode using the MD5
    digest of the default encryption key.
    """

    AES_CCM = 2
    """Authenticated AES128/CCM/NoPadding encryptino mode.

    NOTE: This mode is only present for so-called 'TLS'-devices (UDP
    protocol version must be >= 4).
    """


# Each message MUST be signed except broadcast discovery messages.
class SignType(enum.IntEnum):
    """Signature mode to apply."""

    NONE = 0
    """No message signature"""

    MD5 = 1
    """MD5 signature based on the datagram plus default encryption key."""


# Extra struct:
@bitfield
class WifiDatagramOptions:
    """Controls message encryption and signature mode"""

    # fmt: off
    # Defines the signature mode to apply. There are currently only
    # two modes:
    #   - NONE: no signature
    #   - MD5: digest := MD5(datagram + WIFI_DEFAULT_KEY)
    sign_type : (4, EnumFactory(SignType))    = SignType.NONE

    # Specifies which encryption mode should be applied to the payload.
    # The following modes exist:
    #   - NONE: no encryption
    #   - AES128: encryption using MD5 digest of default encryption key
    #   - AES_CCM: aes encryption that uses TLS session keys with a nonce
    enc_type  : (4, EnumFactory(EncryptType)) = EncryptType.NONE
    # fmt: on


# Extra struct:
@struct
class WifiDatagramTime:
    """Stores the creation time of a Wifi datagram"""

    # fmt: off
    milli   : uint8 = 0
    second  : uint8 = 0
    minute  : uint8 = 0
    hour    : uint8 = 0
    day     : uint8 = 0
    month   : uint8 = 0
    year_lo : uint8 = 0
    year_hi : uint8 = 0
    # fmt: on

    def to_date(self) -> datetime.datetime:
        """Converts the creation time to a datetime object."""
        return datetime.datetime(
            year=int(str(self.year_hi) + str(self.year_lo)),
            month=self.month,
            day=self.day,
            minute=self.minute,
            hour=self.hour,
            microsecond=self.milli * 1000,
        )

    @staticmethod
    def from_date(date: datetime.datetime):
        """Creates a new creation time object from a datetime object."""
        obj = WifiDatagramTime()
        obj.milli = int(date.microsecond / 1000) & 0xFF
        obj.second = date.second
        obj.minute = date.minute
        obj.hour = date.hour
        obj.month = date.month

        # wierd year encoding
        year = str(date.year)
        obj.year_lo = int(year[2:])
        obj.year_hi = int(year[:2])
        return obj

    @staticmethod
    def from_now():
        """Creates a new creation time object from the current time"""
        return WifiDatagramTime.from_date(datetime.datetime.now())


def _wifidatagram_length(context) -> int:
    # The length must be calculated dynamically based on the
    # following rules:
    #   - length zero indicates no body
    #   - AES/CCM mode requires 13 byte nonce
    #   - Version 3 and higher requires two byte sent CNT
    parsed_datagram = context._obj
    length = parsed_datagram.length
    if length == 0:
        return 0

    if _wifidatagram_nonce(context):
        length -= 13

    if _wifidatagram_cnt(context):
        length -= 2

    return length - 56


def _wifidatagram_nonce(context) -> bool:
    # nonce field condition
    parsed_datagram = context._obj
    length = parsed_datagram.length
    return length > 0 and parsed_datagram.options.enc_type == EncryptType.AES_CCM


def _wifidatagram_cnt(context) -> bool:
    # sent CNT field condition
    parsed_datagram = context._obj
    length = parsed_datagram.length
    return length > 0 and parsed_datagram.version >= 3


# The main struct:
@struct(order=LittleEndian)
class WifiDatagram:
    """Describes a message sent over Wifi."""

    # fmt: off
    # ---- HEADER BEGIN ----
    # This field is described as "header" but as well may be defined as
    # constant magic bytes
    magic        : WIFI_HEADER_MARK

    # Defines the datagram version - also called "WifiProVersion". Currently,
    # only two versions should be active:
    #   - 0x01: default version
    #   - 0x03: new version for TLS devices
    version      : uint8                             = 1

    # The next two fields were wrapped into WifiDatagramOptions.
    options      : WifiDatagramOptions

    # The length of the payload PLUS header and signature length. This value
    # can be zero if the payload is empty.
    length       : uint16                            = 0

    # Message type according to the WifiCommand value (may be incomplete)
    msg_type     : WifiCommand

    # A running number usually representing the current message id.
    msg_id       : uint32                            = 0

    # Custom time format within eight bytes
    time         : WifiDatagramTime

    # # DeviceID Format represents a six-byte integer represented as
    # a hex-string
    device_id    : Bytes(6)                          = bytes(6)

    # Response timeout in ??
    resp_timeout : uint16                            = 10000

    # unused channel ID
    channel_id   : Bytes(6)                          = bytes(6)

    # The next six bytes are reserved, but not empty. The following fields
    # seem to be defined but are still unused:
    #   - deviceInfo: fixed value of 32 at index 1 on requests
    #   - authentic : unused value at index 1 on responses
    #   - moduleType: unused value at index 0
    reserved     : Bytes(6)                          = bytes(6)
    # ---- HEADER END ---- (40 bytes)

    # The payload of this datagram. If the device type is "16" (GATE_WAY),
    # only 40 bytes must be subtracted (TODO).
    # - AES_CCM mode additionally introduces a nonce that is prepended to
    #   the payload
    nonce        : Bytes(13) // _wifidatagram_nonce  = bytes(13)
    # - packets of version >= 3 store an additional count  in front of
    #   the payload.
    cnt          : uint16 // _wifidatagram_cnt       = 0
    # the actual body.
    body         : Bytes(_wifidatagram_length)       = bytes()

    # Signature according to the SignType specified in this.options
    signature    : Bytes(16)                         = bytes(16)
    # fmt: on

    @staticmethod
    def from_bytes(data: bytes):
        """Parses a Wifi datagram from the given data stream"""
        return unpack(WifiDatagram, data)

    @staticmethod
    def new(
        msg_type: WifiCommand,
        *,
        body: bytes | None = None,
        enc_type: EncryptType = EncryptType.NONE,
        sign_type: SignType = SignType.NONE,
        device_id: bytes | None = None,
        nonce: bytes | None = None,
        session_keys: bytes | None = None,
    ):
        """Creates a new Wifi datagram with the given message type."""
        datagram = WifiDatagram(
            options=WifiDatagramOptions(sign_type, enc_type),
            msg_type=msg_type,
            time=WifiDatagramTime.from_now(),
            device_id=device_id or bytes(6),
        )
        if body:
            self.set_payload(body, nonce=nonce, session_keys=session_keys)

        return datagram

    def set_payload(
        self,
        body: bytes,
        nonce: bytes | None = None,
        session_keys: bytes | None = None,
    ):
        """Sets the current payload (optionally encrypts it)"""
        match self.options.enc_type:
            # This option should only be present in case of errors and
            # discovery messages
            case EncryptType.NONE:
                self.body = body

            # encryption using MD5 of default key
            #   KEY   := MD5(DEFAULT_KEY)
            #   ENC   := AES128/ECB/PKCS7(KEY, BODY)
            case EncryptType.AES128:
                cipher = Cipher(algorithms.AES128(DEFAULT_KEY_MD5), modes.ECB())
                padder = PKCS7(128).padder()
                enc = cipher.encryptor()

                pad_body = padder.update(body) + padder.finalize()
                self.body = enc.update(pad_body) + enc.finalize()

            # encryption using session keys
            #   KEY    := SESSION_KEYS
            #   NONCE  := BODY[0..13]
            #   AAD    := MSHEADER    := PACKET[0..40]
            #   PLAIN  := BODY
            #   ENC    := NONCE + AES/CCM/NoPadding(KEY, NONCE, AAD, PLAIN)
            case EncryptType.AES_CCM:
                if not nonce or not session_keys:
                    raise ValueError("AES_CCM mode requires a nonce and session keys!")

                header = pack(self)[:40]
                cipher = aead.AESCCM(session_keys)
                enc_body = cipher.encrypt(nonce, body, header)
                self.body = enc_body
                self.nonce = nonce

    def get_payload(self, session_keys: bytes | None = None) -> bytes:
        """Sets a new payload"""
        match self.options.enc_type:
            # This option should only be present in case of errors and
            # discovery messages
            case EncryptType.NONE:
                return self.body

            # encryption using default key
            #   KEY   := MD5(DEFAULT_KEY)
            #   PLAIN := AES128/ECB/PKCS7(KEY, BODY)
            case EncryptType.AES128:
                cipher = Cipher(algorithms.AES128(DEFAULT_KEY_MD5), modes.ECB())
                unpadder = PKCS7(128).unpadder()
                dec = cipher.decryptor()

                dec_body = dec.update(self.body) + dec.finalize()
                return unpadder.update(dec_body) + unpadder.finalize()

            # Encryption mode using session keys
            #   KEY    := SESSION_KEYS
            #   NONCE  := BODY[0..13]
            #   AAD    := MSHEADER    := PACKET[0..40]
            #   ENC    := BODY[13..]
            #   PLAIN  := NONCE + AES/CCM/NoPadding(KEY, NONCE, AAD, ENC)
            case EncryptType.AES_CCM:
                if not session_keys:
                    raise ValueError("AES_CCM mode requires session keys!")

                header = pack(self)[:40]
                cipher = aead.AESCCM(session_keys)
                return cipher.decrypt(self.nonce, self.body, header)

    def update_signature(self):
        """Updates the current packet signature."""
        if self.options.sign_type == SignType.MD5:
            # Signature is:
            #   S  := MD5(BODY + DEFAULT_KEY)
            payload = pack(self)[:-16]
            self.signature = hashlib.md5(payload + DEFAULT_KEY).digest()

    def is_signature_valid(self):
        """Returns whether the current signature is valid."""
        if self.options.sign_type == SignType.NONE:
            return True

        payload = pack(self)[:-16]
        signature = hashlib.md5(payload + DEFAULT_KEY).digest()
        return signature == self.signature

    def build(self) -> bytes:
        """Packs this datagram into bytes."""
        self.length = len(self.body) + 56
        if self.length > 0:
            if self.version >= 3:
                # add sent CNT
                self.length += 2
            if self.options.enc_type == EncryptType.AES_CCM:
                # add nonce
                self.length += 13

        self.update_signature()
        return pack(self)
