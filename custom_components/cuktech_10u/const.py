from __future__ import annotations

DOMAIN = "cuktech_10u"
DEVICE_NAME = "CUKTECH 10 Ultra"

CONF_ADDRESS = "address"
CONF_TOKEN = "token"
CONF_REFRESH_INTERVAL = "refresh_interval"
CONF_FIRMWARE_VERSION = "firmware_version"

DEFAULT_REFRESH_INTERVAL = 0
DEFAULT_SCAN_TIMEOUT = 10

FIRMWARE_VERSION_UUID = "00000004-0000-1000-8000-00805f9b34fb"

UUIDS = {
    "upnp": "00000010-0000-1000-8000-00805f9b34fb",
    "avdtp": "00000019-0000-1000-8000-00805f9b34fb",
    "vendor_1a": "0000001a-0000-1000-8000-00805f9b34fb",
    "cmtp": "0000001b-0000-1000-8000-00805f9b34fb",
    "vendor_1c": "0000001c-0000-1000-8000-00805f9b34fb",
}

MIOT_GET_PROPS_BODY = bytes.fromhex(
    "020f020100020200020300020400020500020600020700020f00020d00021500021300021400021100021200021000"
)

PORT_NAMES = {
    1: "c1",
    2: "c2",
    3: "c3",
    4: "a",
}

PORT_BITS = {
    "c1": 0x01,
    "c2": 0x02,
    "c3": 0x04,
    "a": 0x08,
}

SCENE_MODE_PROPERTY = "scene_mode"
USB_A_LOW_CURRENT_PROPERTY = "usb_a_low_current"

SCENE_MODE_OPTIONS = {
    "AI智能": 1,
    "数码生态": 2,
    "极速单充": 3,
    "均衡输出": 4,
}

SCENE_MODE_VALUES = {value: option for option, value in SCENE_MODE_OPTIONS.items()}

PORT_PROPERTY_NAMES = {
    1: "port-c-one-info",
    2: "port-c-two-info",
    3: "port-c-three-info",
    4: "port-a-info",
}

PROPERTY_NAMES = {
    **PORT_PROPERTY_NAMES,
    5: SCENE_MODE_PROPERTY,
    6: "screen_save_time",
    7: "protocol_ctl",
    13: "device_language",
    15: USB_A_LOW_CURRENT_PROPERTY,
    16: "port_ctl",
    17: "c_one_c_two_protocol",
    18: "c_three_a_protocol",
    19: "screenoff_while_idle",
    20: "screen_dir_lock",
    21: "protocol_ctl_extend",
}

PLATFORMS = ["binary_sensor", "select", "sensor", "switch"]
