# pyright: reportGeneralTypeIssues=false, reportInvalidTypeForm=false
import enum

from caterpillar.shortcuts import bitfield, LittleEndian, struct, opt, this
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

from midea_iot.uart import UartDatagram


# Command requests simply encapsulate UART datagrams.
DeviceCommandRequest = UartDatagram


@struct(options=[opt.S_ADD_BYTES])
class QueryErrorCodeRequest:
    # fmt: off
    # Protocol version, default is 1.
    version      : uint8              = 1

    # Function number for the request, default is 0.
    function_num : uint8              = 0
    reserved     : uint8              = 0
    # fmt: on


# Creates a new request to switch a device from AP (Access Point) mode
# to STA (Station) mode.
#
# The response to this request should be parsed using SwitchAPToSTAResult,
# which extracts the mode byte from the response.
#
# Used in step: SWITCH_STA
def new_SwitchAPToSTARequest() -> bytes:
    return b"\x02"


def new_QueryCombinationRequest() -> bytes:
    return b"\x00"


@struct(options=[opt.S_ADD_BYTES])
class WriteDeviceIDRequest:
    """A request to write device identification information to a device.

    This command is used within the WRITE_DEVICE_ID configuration step phase and
    simply writes the serial number and device ID collected from the broadcast
    packet.
    """

    # Device serial number (up to 32 ASCII characters).
    device_sn: Bytes(32)

    # DeviceId NOT as a hex string - MUST be manually converted to a
    # hex string
    device_id: Bytes(6)


# Target WiFi encryption type. Note that WPA also includes WPA2
class RouterEncryptType(enum.IntEnum):
    __struct__ = uint8

    NONE = 0
    WEP = 1
    WPA = 2
    EAP = 3


@struct(options=[opt.S_ADD_BYTES])
class WriteWifiCfgRequest:
    """Command payload to write Wi-Fi configuration to a device

    Used in step: WRITE_WIFI_CONFIGURATION
    """

    # fmt: off
    # Type of Wi-Fi encryption (e.g., WPA2).
    encrypt_type    : RouterEncryptType

    # Both, SSID and password lengths are stored before the actual
    # content, making the struct unnecessarily complex.
    ssid_len        : uint8 = 0
    pwd_len         : uint8 = 0

    # Target Wi-Fi network SSID (name).
    ssid            : Bytes(this.ssid_len)

    # Target Wi-Fi network password.
    pwd             : Bytes(this.pwd_len)
    # fmt: on

    @staticmethod
    def new(encrypt_type: RouterEncryptType, ssid: bytes, pwd: bytes):
        """Construct a WriteWifiCfgRequest with SSID, password, and encryption type."""
        return WriteWifiCfgRequest(
            encrypt_type=encrypt_type,
            ssid_len=len(ssid),
            ssid=ssid,
            pwd_len=len(pwd),
            pwd=pwd,
        )


@struct
class WifiConfigRequest:
    """Same class as WriteWifiCfgRequest but for UDP protocol version 2 and 3.

    Used in step: WRITE_WIFI_CONFIGURATION
    """

    # ...
