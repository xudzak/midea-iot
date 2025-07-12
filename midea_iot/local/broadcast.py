# pyright: reportGeneralTypeIssues=false, reportInvalidTypeForm=false
import enum

from caterpillar.shortcuts import bitfield, LittleEndian, struct, opt
from caterpillar.model import unpack, pack
from caterpillar.fields import uint8, uint16, uint32, boolean
from caterpillar.py import (
    EnumFactory,
    Bytes,
    IPv4Address,
    Prefixed,
    MAC,
    Enum,
    EndGroup,
)

from midea_iot.util import Bcd
from midea_iot.const import Category


# Describes the identification type of a device. These values are based on the
# old Android SDK. There might be more added later on - this can't be verified.
class IdentificationType(enum.IntEnum):
    DEVICE = 0
    """Message sent by device"""

    SDK = 1
    """Message sent by the iOS/Android SDK"""


# Configuration generation type specified by the UDP protocol version number.
class UdpVersion(enum.IntEnum):
    __struct__ = uint32

    # fmt: off
    FIRST_GEN  = 0
    SECOND_GEN = 1
    THIRD_GEN  = 2
    FOUR_GEN   = 3  # yes, its named CONFIGURATION_TYPE_FOUR_GENERATION
    FIVE_GEN   = 4  # CONFIGURATION_TYPE_FIVE_GENERATION
    # fmt: on


# Identification information for the current message. This struct hasn't changed
# since version 3.1.5. The newest version marks all attributes of this struct as
# @depcrecated
@bitfield(options={opt.S_DISCARD_UNNAMED})
class Identification:
    # fmt: off
    id_timeout      : 4                                     = 0
    _               : 3
    id_type         : (1, EnumFactory(IdentificationType))  = IdentificationType.SDK
    reserved        : uint8                                 = 0
    # fmt: on


# These options are relatively new to the packet format and their documentation
# is far from being complete. This struct uses two bytes of eight bits each.
@bitfield(options={opt.S_DISCARD_UNNAMED})
class Extra:
    # fmt: off
    # Enables the use and definition of all other extra variables.
    enable_extra                   : 1             = False
    _                              : 1

    # Tells the SDK whether a device supports configuration depending on the
    # current region ID. This region identifier will be set in the
    # WifiConfigRequest.
    region_id_enabled              : 1             = False

    # Tells the SDK whether the device supports fetching the last error code
    # when configuring Wifi.
    supports_query_error_code      : 1             = False
    supports_reenter_config        : 1             = False

    # Enables the error_code field in the DeviceScanResult struct (code must
    # be non-zero).
    supports_extra_last_error_code : 1             = False

    # Indicates custom Wifi-Channel support.
    supports_extra_channel         : 1             = False

    # also described as "authenticationEnable" - not used anywhere
    supports_extra_auth            : (1, EndGroup) = False

    # -- start 2nd byte --
    _1                             : 3

    # Indicates that the device supports the COMMAND_QUERY_COMBINATION_REQUEST,
    # which has an empty body.
    combination_enabled            : 1             = False

    # Indicates that ADNS IPs are supported.
    adns_enabled                   : 1             = False
    _2                             : 1

    # no usage - maybe that configuration over UDP channel is supported too.
    supports_udp_config            : 1             = False
    function_set_enabled           : 1             = False
    # fmt: on


# The main struct:
@struct(order=LittleEndian)
class DeviceScanResult:
    """Heartbeat packet or scan result packet."""

    # fmt: off
    # The current device IP address within the local Wifi
    device_ip           : IPv4Address

    # Current device configuration / communication port to use. By default,
    # only TCP connections are supported.
    device_port         : uint32

    # Serial number of the device (hex string) If the UDP protocol version
    # is >= 3, this serial number is encrypted using the following scheme:
    #   TIMESTAMP  := WifiDatagram.timestamp
    #   ENC_SN     := byte[32]
    #   SALT       := SHA256(TIMESTAMP)
    #   KEY        := PBKDF2/Hmac/SHA256(CLOUD_PRIVATE_KEY, SALT, 1024, 256)
    #   PLAIN_SN   := AES/CBC/NoPadding(ENC_SN, KEY, S_E_CBC_IV)
    #
    # NOTE: S_E_CBC_IV is define in const.py; CLOUD_PRIVATE_KEY must be obtained
    # from the cloud.
    #   - /v2/open/sdk/appliance/privateKey2: overseas private key
    #   - /v1/appliance/AKA/privateKey: inland private key
    device_sn           : Bytes(32)

    # Stores the default Wifi access point SSID of the device.
    device_ssid         : Prefixed(uint8, encoding="utf-8")

    # @deprecated: Identification information of the device
    ident               : Identification

    # A bitfield of extra configuration information. These might affect the
    # behaviour of the SDK.
    extra               : Extra

    # Protocol version number / configuration generation type.
    udp_version         : UdpVersion
    protocol_code       : uint8
    function_reserved   : Bytes(2)
    master_gateway      : uint8
    manufacturer_code   : Bytes(2)

    # Stores the device type in one byte. The second byte seems to be reserved
    # and remains unused
    device_type         : Enum(Category, uint8)
    _type_reserved      : uint8 = 0

    # Same applies to the subtype - this seems to be a two byte hex value.
    device_subtype      : uint16
    _subtype_reserved   : Bytes(4)

    # The device's MAC.
    device_mac          : MAC

    # Custom Binary-Coded-Decimal encoding applied to the protocol version.
    protocol_version    : Bcd(Bytes(6))

    # Indicates whether the device is connected to the cloud.
    server_connected    : boolean
    max_tcp_count       : uint8
    current_tcp_count   : uint8

    # Maybe used as verification after configuration?
    random_code         : Bytes(16)

    # The following fields are defined but unused except 'error_code'. This
    # field is enabled if 'supports_extra_last_error_code' in this.extra
    # has been set.
    environment         : Bytes(2)
    port_reserved       : uint16
    error_code          : uint8
    timestamp           : Bytes(8)
    reserved            : Bytes(4)
    # fmt: on

    @staticmethod
    def from_bytes(data: bytes):
        return unpack(DeviceScanResult, data)
