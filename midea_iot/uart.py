# pyright: reportGeneralTypeIssues=false, reportInvalidTypeForm=false
import enum
import random

from caterpillar.shortcuts import bitfield, LittleEndian, struct, this
from caterpillar.model import unpack, pack
from caterpillar.fields import uint8, uint16, uint32
from caterpillar.py import EnumFactory, Bytes, Enum

from midea_iot.const import Category

# Custom commands are encoded using a special datagram format called
# 'UartDatagram'. Though its name seems to be linked to UART communication,
# this protocol is also used within Wifi messages.


# default defined message types
class MsgType(enum.IntEnum):
    __struct__ = uint8

    # fmt: off
    BASIC_INFO_QUERY                        = 160
    DEV_CONTROL                             = 2
    DEV_QUERY                               = 3
    DEV_RUNNING_STATE_REPORT                = 4
    DEV_RUNNING_STATE_REPORT_NEED_RESPONSE  = 5
    DEV_ERROR_REPORT                        = 6
    DEV_GET_SN                              = 7
    DEV_ERROR_REPORT_NEED_RESPONSE          = 10
    DEV_NET_CONNECTED                       = 13
    # fmt: on


UART_HEADER_MARK = b"\xaa"
"""Header magic for UART datagrams"""


# Internal data transmit datagram called 'UartDatagram'. Only BASIC_INFO_QUERY is
# used within the SDK.
@struct
class UartDatagram:
    """Internal datagram format."""

    # fmt: off
    # Constant header of this datagram. Must be ßxAA.
    magic            : UART_HEADER_MARK

    # Describes the whole length of this datagram, including the header
    # and the checksum at the end:
    #   HEADER_LEN  := 10
    #   CRC_LEN     := 1
    #   LENGTH      := HEADER_LEN + Len(BODY) + CRC_LEN
    length           : uint8                    = 0

    # Specifies the device type to target. This property usually should be filled
    # using the response value from the broadcast response.
    device_type      : Enum(Category, uint8)    = 0

    # Stores another check-code (no checksum) based on the length without
    # the extra checksum length:
    #   HEADER_LEN  := 10
    #   FCC         := Xor(HEADER_LEN + Len(BODY), DEVICE_TYPE)
    frame_check_code : uint8                    = 0 # FCC == Frame Check Code

    # unused, SHOULD be filled with zeros
    reserved         : Bytes(2)                 = bytes(2)

    # The message Id SHOULD be always a random integer for request
    # datagrams.
    msg_id           : uint8                    = 0

    # RESERVED: version and protocol version is currently set to zero
    version          : uint8                    = 0
    protocol_version : uint8                    = 0

    # The message (MUST be identical with the one specified in the WifiDatagram).
    msg_type         : MsgType

    # The actual payload of this datagram.
    body             : Bytes(this.length - 11)  = bytes()

    # A check code introduced to verify the contents of this message. It is
    # caluclated as follows:
    #   INIT    := Sum(LENGTH, DEVICE_TYPE, FCC, MSG_ID, VERSION, \
    #                  PROTOCOL_VERSION, MSG_TYPE)
    #   CC      := BitNot(Sum(INIT, ...BODY)) + 1
    check_code       : uint8                    = 0 # CC == Check Code
    # fmt: on

    def get_check_code(self):
        """Calculates the check code (CC) for the current datagram"""
        value = (
            self.length
            + self.device_type
            + self.frame_check_code
            + self.msg_id
            + self.version
            + self.protocol_version
            + int(self.msg_type)
        ) + sum(self.body)
        value &= 0xFFFFFFFF
        return ((~value) + 1) & 0xFF

    def get_frame_check_code(self):
        """Calculates the frame check code (FCC) for the current datagram."""
        return (int(self.device_type) ^ (len(self.body) + 10)) & 0xFF

    def build(self) -> bytes:
        """Packs this datagram into its serialized representation."""
        self.length = (10 + len(self.body)) & 0xFF
        self.frame_check_code = self.get_frame_check_code()
        self.check_code = self.get_check_code()
        # crc size at the end
        self.length += 1
        return pack(self)

    @staticmethod
    def from_bytes(data: bytes):
        """Parses the given data as a datagram."""
        return unpack(UartDatagram, data)

    @staticmethod
    def new(
        msg_type: MsgType,
        /,
        *,
        device_type: Category | None = None,
        body: bytes | None = None,
        msg_id: int | None = None,
    ):
        """Builds a new UART datagram (internal transmit datagram)"""
        if msg_id is None:
            msg_id = random.randrange(0, 254) + 1
        return UartDatagram(
            msg_type=msg_type,
            msg_id=msg_id,
            body=body or b"",
            device_type=device_type or 0,
        )
