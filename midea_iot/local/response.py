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
from midea_iot.const import CODE_SUCCESS

# Result type for direct device commands.
#
# Response to: DEVICE_DATA_TRANSMIT
# Code: DEVICE_DATA_TRANSMIT_RESPONSE
DeviceCommandRequest = UartDatagram


# Identified error codes so far.
class ErrorCode(enum.IntEnum):
    __struct__ = uint8

    SUCCESS = CODE_SUCCESS
    CODE_CHANNELLIST_ERROR = 26
    CODE_COUNTRYCODE_ERROR = 24
    CODE_SERVER_DOMAIN_ERROR = 27
    CODE_TIMEZONE_ERROR = 25
    # These next errors are defined within the SDK but don't
    # seem to make any sense.
    FAILED_10_ERROR = 10
    FAILED_5_ERROR = 5
    FAILED_6_ERROR = 6
    FAILED_7_ERROR = 7
    FAILED_8_ERROR = 8
    FAILED_9_ERROR = 9
    FAILED_BSSID_INVALID = 3
    FAILED_PASSWORD_ERROR = 4
    FAILED_PASSWORD_INVALID = 2
    FAILED_SSID_INVALID = 1


@struct(options=[opt.S_ADD_BYTES])
class WriteDeviceIDResult:
    """Response upon writing a new device ID.

    Response to: WRITE_DEVICE_ID
    Code: WRITE_DEVICE_ID_RESPONSE
    """

    # The newly written device ID
    device_id: Bytes(...)


@struct(options=[opt.S_ADD_BYTES])
class WriteWifiCfgResult:
    """Response to writing a new WiFi config (earlier protocol versions)

    Response to: WRITE_WIFI_INFO
    Code: WRITE_WIFI_INFO_RESPONSE
    """

    # fmt: off
    # Error code why the configuration failed. (REVISIT: There seems to be
    # no qualified list of error codes for this one)
    fail_reason : uint8

    # Result code of the operation. This value is set to zero (0) if successful.
    result      : ErrorCode
    # fmt: on


@struct(options=[opt.S_ADD_BYTES])
class QueryErrorCodeResult:
    """Last configuration error information response.

    Response to: QUERY_ERROR_REQUEST
    Code: QUERY_ERROR_RESPONSE
    """

    # fmt: off
    # Version number and function num SHOULD be identical to the
    # ones specified in the request.
    version        : uint8                              = 1
    function_num   : uint8                              = 0

    # Error code. Identified codes so far were defined for
    # WifiConfigResult used in newer protocol and device versions.
    error_code     : ErrorCode                          = ErrorCode.SUCCESS

    # The target configured SSID
    ssid           : Prefixed(uint8, encoding="utf-8")  = str()

    # Whether a password has been configured
    has_password   : boolean                            = False

    # The SHA256 hash of the password (if configured)
    password_sha   : Bytes(32)    // this.has_password  = None
    # fmt: on


@struct(options=[opt.S_ADD_BYTES])
class SwitchAPToSTAResult:
    """Result after trying to switch to station mode. (STA)"""

    mode: uint8


@struct(options=[opt.S_ADD_BYTES])
class WifiConfigResult:
    """Newer version of `WriteWifiCfgResult`."""

    error_code: ErrorCode
