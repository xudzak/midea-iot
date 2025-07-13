import hashlib
import enum

# Default signing and encryption key for Wifi datagrams
DEFAULT_KEY = b"xhdiwjnchekd4d512chdjx5d8e4c394D2D7S"
DEFAULT_KEY_MD5 = hashlib.md5(DEFAULT_KEY).digest()

# Initialization vector for decryption of serial numbers and
# so-called 'tid' values for UDP packets targeting version
# 3 and above.
S_E_CBC_IV = bytes.fromhex("7aa4e56f4f4f04282735a342937073a8")

# fmt: off
# Currently, there are multiple environments active that apply different
# IOT and encryption keys.
#   - <ENV>_IOT_SECRET: serves as the application key, which is used
#     for decrypting LUA object files and signing normal API requests.
#   - <ENV>_MUC_SECRET: Secret for signing HTTP API secret requests
#   - <ENV>_MAS_KEY: Master key for signing API secret requests
DEV_IOT_SECRET  = "143320d6c73144d083baf9f5b1a7acc9"
DEV_MUC_SECRET  = "dev_secret123@muc"
DEV_MAS_KEY     = "DEV_TZJn6TXxmtTHclKk"

PROD_IOT_SECRET = "ad0ee21d48a64bf49f4fb583ab76e799"
PROD_MUC_SECRET = "prod_secret123@muc"
PROD_MAS_KEY    = "PROD_VnoClJI9aikS8dyy"
PROD_APP_KEY    = "becf36de9a484a1494c3e7ac8bd2f98c"

SIT_IOT_SECRET  = DEV_IOT_SECRET
SIT_MUC_SECRET  = "sit_secret123@muc"
SIT_MAS_KEY     = "SIT_4VjZdg19laDoIrut"
SIT_APP_KEY     = "b8f033ca482c4f4695be967ee8c8006e"

UAT_IOT_SECRET  = PROD_IOT_SECRET
UAT_MUC_SECRET  = PROD_MUC_SECRET
UAT_MAS_KEY     = PROD_MAS_KEY

# these keys are unused
DEFAULT_APP_KEY = "c8c35003cc4c408581043baad45bce5b"
DEFAULT_SECRET  = "0dc6fe93a8154fcaab629353ab800bb4"
# fmt: on
# What are 'secret API requests'? The source code of the SDK contains one
# HttpUtil class that is not used unfortunately, BUT it contains the following
# function (psudo-code):
#   def getPostRequest(body, url, jsonString, accessToken):
#       return Request.post(url, body)
#                     .header("Content-Type", "application/json")
#                     .header("sign", sign(jsonString, random))
#                     .header("random", random)
#                     .header("accessToken", accessToken)
#                     .header("secretVersion", "1")
#
# The sign() method implements the following HMAC signature:
#   BODY    := <text>
#   RANDOM  := STRING(NextRandom<double>())
#   KEY     := <ENV>_MAS_KEY
#   SECRET  := <ENV>_MUC_SECRET
#   SIGN    := Hmac/SHA256(KEY, SECRET + BODY + RANDOM)

# Bluetooth key agreement encryption key
BLE_KA_KEY = "midea_blekeyc"

# Password necessary to enter engineering mode within the app
B2B_ENGINEERING_MODE_KEY = "69608"


# Default success error code
CODE_SUCCESS = 0

# ---


class Category(enum.IntEnum):
    AIR_CLEANER = 0xFC
    AIR_CONDITION = 0xAC
    AIR_CONDITION_FAN = 0xFE
    BLACKHEAD_INSTRUMENT = 0x2D
    BLE_GATE_WAY = 0x1A
    BREAD_MAKER = 0xE9
    CENTRAL_AIR_CONDITION = 0xCC
    CLOTHES_DRYER = 0xDC
    CLOTHES_HORSE = 0x17
    CLOTHING_CARE_CABINET = 0x46
    CONTROL_PANEL = 0x44
    DEHUMIDIFIER = 0xA1
    DISH_WASHER = 0xE1
    DRUM_WASHING_MACHINE = 0xDB
    DUPLEX_WASHING_MACHINE = 0xD9
    ELECTRIC_HEATER = 0xFB
    FAN = 0xFA
    GATE_WAY = 0x16
    HEALTH_SCALE = 0x0F
    HEATER = 0xE2
    HEATER_GAS = 0xE3
    HUMIDIFIER = 0xFD
    KITCHEN_SCALE = 0xC0
    MICROWAVE_OVEN = 0xB0
    MIDEA_ROUTER = 0x1B
    MINI_GATE_WAY = 0x2A
    ORAL_IRRIGATOR = 0x31
    OVEN_BIG = 0xB1
    OVEN_SMALL = 0xB4
    PULSATOR_WASHING_MACHINE = 0xDA
    REFRIGERATOR = 0xCA
    RICE_COOKER = 0xEA
    SHOE_BOX = 0x47
    SOCKET = 0x10
    SOUND_BOX = 0x1C
    STEAM_BOILER = 0xB2
    SUB_DEVICE_1 = 0x21
    SUB_DEVICE_DOOR_LOCK = 0x20
    SWEEPER = 0xB8
    VENTILATOR = 0xB6
    WATER_PURIFIER = 0xED
    YS_CAMERA = 0x2B
