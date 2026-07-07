from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
import logging
import secrets
from time import monotonic
from typing import Any

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import BleakOutOfConnectionSlotsError, establish_connection
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.util.dt import utcnow

from .const import FIRMWARE_VERSION_UUID, MIOT_GET_PROPS_BODY, PORT_NAMES, PROPERTY_NAMES, UUIDS

_LOGGER = logging.getLogger(__name__)
_LOG_HEX_BYTES = 24

UpdateCallback = Callable[["CuktechUpdate"], None]
StatusCallback = Callable[[bool], None]
FirmwareCallback = Callable[[str], None]
WriteCallback = Callable[[str, bytes], Awaitable[None]]
VendorFrameCallback = Callable[[bytes], Awaitable[None]]


class CuktechAuthError(Exception):
    """Raised when the Xiaomi Mi auth token is rejected by the charger."""


@dataclass
class PortReading:
    raw_hex: str
    bytes_le: str
    active: bool
    state_byte: int
    protocol_byte: str
    current_est_a: float
    voltage_est_v: float
    power_est_w: float


@dataclass
class CuktechUpdate:
    address: str
    ports: dict[str, PortReading] = field(default_factory=dict)
    properties: dict[str, int] = field(default_factory=dict)
    total_power_w: float = 0.0
    ts: str = field(default_factory=lambda: utcnow().isoformat())


@dataclass(frozen=True)
class ControlCommand:
    piid: int
    value: int
    marker: bytes = bytes.fromhex("0110")
    pre_control: bool = False


def _parse_token(token_hex: str) -> bytes:
    token = bytes.fromhex(token_hex.replace(" ", "").replace(":", ""))
    if len(token) != 12:
        raise ValueError(f"Mi auth token must be 12 bytes, got {len(token)}")
    return token


def _derive_login(token: bytes, app_random: bytes, dev_random: bytes) -> tuple[bytes, bytes, dict[str, bytes]]:
    salt_app = app_random + dev_random
    salt_dev = dev_random + app_random
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt_app,
        info=b"mible-login-info",
    ).derive(token)
    keys = {
        "dev_key": derived[:16],
        "app_key": derived[16:32],
        "dev_iv": derived[32:36],
        "app_iv": derived[36:40],
    }

    app_hmac = hmac.HMAC(keys["app_key"], hashes.SHA256())
    app_hmac.update(salt_app)

    dev_hmac = hmac.HMAC(keys["dev_key"], hashes.SHA256())
    dev_hmac.update(salt_dev)
    return app_hmac.finalize(), dev_hmac.finalize(), keys


def _encrypt_session_payload(key: bytes, iv: bytes, counter: int, plaintext: bytes) -> bytes:
    nonce = iv + bytes(4) + counter.to_bytes(4, "little")
    return AESCCM(key, tag_length=4).encrypt(nonce, plaintext, None)


def _decrypt_session_payload(key: bytes, iv: bytes, counter: int, ciphertext: bytes) -> bytes:
    nonce = iv + bytes(4) + counter.to_bytes(4, "little")
    return AESCCM(key, tag_length=4).decrypt(nonce, ciphertext, None)


def _build_get_prop_frames(keys: dict[str, bytes]) -> list[bytes]:
    frames: list[bytes] = []
    for counter in (0, 1, 2, 7):
        if counter == 0:
            plaintext = bytes.fromhex("05200200f0")
        else:
            plaintext = bytes([0x33, 0x20, counter + 2, 0x00]) + MIOT_GET_PROPS_BODY
        ciphertext = _encrypt_session_payload(keys["app_key"], keys["app_iv"], counter, plaintext)
        frames.append(bytes.fromhex("0100") + counter.to_bytes(2, "little") + ciphertext)
    return frames


def _encrypt_vendor_frame(keys: dict[str, bytes], counter: int, plaintext: bytes) -> bytes:
    ciphertext = _encrypt_session_payload(keys["app_key"], keys["app_iv"], counter, plaintext)
    return bytes.fromhex("0100") + counter.to_bytes(2, "little") + ciphertext


def _build_pre_control_plaintext(counter: int) -> bytes:
    return bytes([0x24, 0x20, (counter + 2) & 0xFF, 0x00]) + bytes.fromhex(
        "020a020800020900020a00020b00020c00020100020200020300020400021000"
    )


def _build_set_uint8_plaintext(counter: int, piid: int, marker: bytes, value: int) -> bytes:
    return (
        bytes([0x0C, 0x20, (counter + 2) & 0xFF, 0x00])
        + bytes.fromhex("000102")
        + bytes([piid & 0xFF, 0x00])
        + marker
        + bytes([value & 0xFF])
    )


def _port_reading(value: int) -> PortReading:
    raw = value.to_bytes(4, "little", signed=False)
    active = raw[0] != 0
    current_a = raw[2] / 10.0
    voltage_v = raw[3] / 10.0
    power_w = current_a * voltage_v if active else 0.0
    return PortReading(
        raw_hex=f"0x{value:08x}",
        bytes_le=raw.hex(" "),
        active=active,
        state_byte=raw[0],
        protocol_byte=f"0x{raw[1]:02x}",
        current_est_a=current_a,
        voltage_est_v=voltage_v,
        power_est_w=round(power_w, 3),
    )


def parse_miot_payload(address: str, payload: bytes) -> CuktechUpdate | None:
    if len(payload) < 6 or payload[1] != 0x20:
        return None

    ports: dict[str, PortReading] = {}
    properties: dict[str, int] = {}

    if payload[0] == 0x93:
        offset = 6
    elif payload[0] == 0x0F:
        offset = 6
    else:
        return None

    while offset + 7 <= len(payload):
        siid = payload[offset]
        piid = payload[offset + 1]

        marker_offset = -1
        if payload[offset + 5 : offset + 7] in (
            bytes.fromhex("0450"),
            bytes.fromhex("0110"),
            bytes.fromhex("0100"),
            bytes.fromhex("0230"),
        ):
            marker_offset = offset + 5
        elif payload[offset + 3 : offset + 5] in (
            bytes.fromhex("0450"),
            bytes.fromhex("0110"),
            bytes.fromhex("0100"),
            bytes.fromhex("0230"),
        ):
            marker_offset = offset + 3
        if marker_offset == -1:
            break

        marker = payload[marker_offset : marker_offset + 2]
        value_offset = marker_offset + 2
        prop_name = PROPERTY_NAMES.get(piid, f"siid_{siid}_piid_{piid}")

        if marker == bytes.fromhex("0450") and value_offset + 4 <= len(payload):
            value = int.from_bytes(payload[value_offset : value_offset + 4], "little", signed=False)
            properties[prop_name] = value
            if siid == 2 and piid in PORT_NAMES:
                ports[PORT_NAMES[piid]] = _port_reading(value)
            offset = value_offset + 4
        elif marker in (bytes.fromhex("0110"), bytes.fromhex("0100")) and value_offset < len(payload):
            properties[prop_name] = payload[value_offset]
            offset = value_offset + 1
        elif marker == bytes.fromhex("0230") and value_offset + 2 <= len(payload):
            properties[prop_name] = int.from_bytes(payload[value_offset : value_offset + 2], "little")
            offset = value_offset + 2
        else:
            break

    if not ports and not properties:
        return None

    total = sum(port.power_est_w for port in ports.values())
    return CuktechUpdate(
        address=address,
        ports=ports,
        properties=properties,
        total_power_w=round(total, 3),
    )


def _char_by_uuid(client: BleakClient, uuid: str) -> Any:
    uuid = uuid.lower()
    for service in client.services:
        for char in service.characteristics:
            if str(char.uuid).lower() == uuid:
                return char
    raise RuntimeError(f"Characteristic {uuid} not found")


def _format_bytes(value: bytes, limit: int = _LOG_HEX_BYTES) -> str:
    if len(value) <= limit:
        return value.hex()
    head_len = limit // 2
    tail_len = limit - head_len
    return f"{value[:head_len].hex()}...{value[-tail_len:].hex()}"


def _format_property_debug(piid: int, value: int) -> str:
    return f"piid={piid} property={PROPERTY_NAMES.get(piid, 'unknown')} value={value}"


async def _async_write_char(client: BleakClient, char: Any, value: bytes, name: str | None = None) -> None:
    props = getattr(char, "properties", None) or ()
    response = "write" in props
    _LOGGER.debug(
        "CUKTECH write %s uuid=%s len=%s response=%s value=%s",
        name or "unknown",
        char.uuid,
        len(value),
        response,
        _format_bytes(value),
    )
    await client.write_gatt_char(char, value, response=response)
    await asyncio.sleep(0.08)


def _decode_firmware_version(value: bytes) -> str | None:
    text = value.rstrip(b"\x00").decode("ascii", errors="ignore").strip()
    return text or None


class Cuktech10UClient:
    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        token_hex: str,
        refresh_interval: int,
        update_callback: UpdateCallback,
        status_callback: StatusCallback,
        firmware_callback: FirmwareCallback,
    ) -> None:
        self._hass = hass
        self._address = address.upper()
        self._token = _parse_token(token_hex)
        self._refresh_interval = refresh_interval
        self._update_callback = update_callback
        self._status_callback = status_callback
        self._firmware_callback = firmware_callback
        self._control_queue: asyncio.Queue[ControlCommand] = asyncio.Queue()

    async def async_set_port_mask(self, mask: int) -> None:
        await self.async_set_uint8_property(16, mask & 0x0F, pre_control=True)

    async def async_set_uint8_property(
        self,
        piid: int,
        value: int,
        marker: bytes = bytes.fromhex("0110"),
        pre_control: bool = False,
    ) -> None:
        _LOGGER.debug(
            "Queued CUKTECH control for %s: %s marker=%s pre_control=%s queue_size=%s",
            self._address,
            _format_property_debug(piid, value),
            marker.hex(),
            pre_control,
            self._control_queue.qsize(),
        )
        await self._control_queue.put(ControlCommand(piid=piid, value=value, marker=marker, pre_control=pre_control))

    async def async_run(self, stop_event: asyncio.Event) -> None:
        backoff = 5
        while not stop_event.is_set():
            try:
                _LOGGER.info("Starting CUKTECH BLE session for %s", self._address)
                await self._async_run_session(stop_event)
                backoff = 5
            except asyncio.CancelledError:
                raise
            except CuktechAuthError as exc:
                self._status_callback(False)
                _LOGGER.warning(
                    "CUKTECH BLE auth failed for %s; retrying in %s seconds: %s",
                    self._address,
                    backoff,
                    exc,
                )
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 60)
            except (BleakOutOfConnectionSlotsError, BleakError) as exc:
                self._status_callback(False)
                _LOGGER.warning(
                    "CUKTECH BLE device %s is unavailable; retrying in %s seconds: %s",
                    self._address,
                    backoff,
                    exc,
                )
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 60)
            except Exception as exc:
                self._status_callback(False)
                _LOGGER.warning(
                    "CUKTECH BLE session for %s failed; retrying in %s seconds: %s",
                    self._address,
                    backoff,
                    exc,
                    exc_info=True,
                )
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 60)

    async def _async_get_ble_device(self) -> Any:
        ble_device = bluetooth.async_ble_device_from_address(self._hass, self._address, connectable=True)
        if ble_device is not None:
            _LOGGER.info("Found CUKTECH BLE device %s from Home Assistant Bluetooth cache", self._address)
            return ble_device

        _LOGGER.info("CUKTECH BLE device %s not in cache; requesting active scan", self._address)
        await bluetooth.async_request_active_scan(self._hass)
        ble_device = bluetooth.async_ble_device_from_address(self._hass, self._address, connectable=True)
        if ble_device is None:
            raise RuntimeError(f"No connectable Bluetooth device for {self._address}")
        _LOGGER.info("Found CUKTECH BLE device %s after active scan", self._address)
        return ble_device

    async def _async_run_session(self, stop_event: asyncio.Event) -> None:
        target = await self._async_get_ble_device()
        rcv_rdy_event = asyncio.Event()
        dev_random_event = asyncio.Event()
        dev_info_event = asyncio.Event()
        upnp_status_event = asyncio.Event()
        greeting_event = asyncio.Event()
        disconnected_event = asyncio.Event()
        update_event = asyncio.Event()
        vendor_ready_event = asyncio.Event()
        vendor_done_event = asyncio.Event()

        state: dict[str, Any] = {
            "greeting_count": 0,
            "rcv_rdy_count": 0,
            "dev_random": None,
            "dev_info": None,
            "upnp_status": None,
            "session_keys": None,
            "next_counter": 8,
            "initial_get_props_sent": False,
            "pre_control_sent": False,
            "parcel_kind": None,
            "parcel_expected_frames": 0,
            "parcel_data": bytearray(),
            "vendor_ready_event": vendor_ready_event,
            "vendor_done_event": vendor_done_event,
        }

        def disconnected_callback(_client: BleakClient) -> None:
            disconnected_event.set()

        client = await establish_connection(
            BleakClient,
            target,
            self._address,
            disconnected_callback=disconnected_callback,
        )
        _LOGGER.info("Connected to CUKTECH BLE device %s", self._address)
        try:
            chars = {name: _char_by_uuid(client, uuid) for name, uuid in UUIDS.items()}
            await self._async_read_firmware_version(client)
            protocol_lock = asyncio.Lock()

            async def write_name_unlocked(name: str, value: bytes) -> None:
                await _async_write_char(client, chars[name], value, name)

            async def write_name(name: str, value: bytes) -> None:
                async with protocol_lock:
                    await write_name_unlocked(name, value)

            async def send_vendor_frame(frame: bytes) -> None:
                async with protocol_lock:
                    await self._async_send_vendor_frame(write_name_unlocked, state, frame)

            async def on_notify(name: str, _sender: Any, data: bytearray) -> None:
                value = bytes(data)
                _LOGGER.debug("CUKTECH notify %s len=%s value=%s", name, len(value), _format_bytes(value))
                if name == "vendor_1a":
                    if value == bytes.fromhex("00000101"):
                        vendor_ready_event.set()
                    elif value == bytes.fromhex("00000100"):
                        vendor_done_event.set()
                    else:
                        _LOGGER.debug("CUKTECH vendor_1a status for %s: %s", self._address, value.hex())
                elif name == "avdtp" and value.startswith(bytes.fromhex("000004")):
                    state["greeting_count"] += 1
                    greeting_event.set()
                    await write_name("avdtp", bytes.fromhex("000005") + value[3:])
                elif name == "avdtp" and value == bytes.fromhex("00000101"):
                    state["rcv_rdy_count"] += 1
                    rcv_rdy_event.set()
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000000d")) and len(value) >= 6:
                    state["parcel_kind"] = 0x0D
                    state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                    state["parcel_data"] = bytearray()
                    await write_name("avdtp", bytes.fromhex("00000101"))
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000000c")) and len(value) >= 6:
                    state["parcel_kind"] = 0x0C
                    state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                    state["parcel_data"] = bytearray()
                    await write_name("avdtp", bytes.fromhex("00000101"))
                elif (
                    name == "avdtp"
                    and state["parcel_kind"] is not None
                    and len(value) >= 2
                    and 1 <= value[0] <= state["parcel_expected_frames"]
                ):
                    frame_no = value[0] + value[1] * 0x100
                    state["parcel_data"].extend(value[2:])
                    if frame_no == state["parcel_expected_frames"]:
                        if state["parcel_kind"] == 0x0D:
                            state["dev_random"] = bytes(state["parcel_data"])
                            dev_random_event.set()
                        elif state["parcel_kind"] == 0x0C:
                            state["dev_info"] = bytes(state["parcel_data"])
                            dev_info_event.set()
                        state["parcel_kind"] = None
                        state["parcel_expected_frames"] = 0
                        state["parcel_data"] = bytearray()
                        await write_name("avdtp", bytes.fromhex("00000300"))
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000020d")):
                    state["dev_random"] = value[4:]
                    dev_random_event.set()
                    await write_name("avdtp", bytes.fromhex("00000300"))
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000020c")):
                    state["dev_info"] = value[4:]
                    dev_info_event.set()
                    await write_name("avdtp", bytes.fromhex("00000300"))
                elif name == "upnp":
                    state["upnp_status"] = value
                    upnp_status_event.set()
                elif name == "cmtp" and value.startswith(bytes.fromhex("000002")):
                    await write_name("cmtp", bytes.fromhex("00000300"))
                    keys = state["session_keys"]
                    if keys and len(value) > 10:
                        counter = int.from_bytes(value[4:6], "little")
                        try:
                            plaintext = _decrypt_session_payload(keys["dev_key"], keys["dev_iv"], counter, value[6:])
                        except Exception as exc:
                            _LOGGER.debug("Failed to decrypt CMTP payload: %s", exc, exc_info=True)
                            return
                        if update := parse_miot_payload(self._address, plaintext):
                            _LOGGER.debug(
                                "Received CUKTECH update for %s: total=%sW ports=%s",
                                self._address,
                                update.total_power_w,
                                ",".join(sorted(update.ports)),
                            )
                            self._update_callback(update)
                            update_event.set()

            subscribed: list[str] = []
            loop = asyncio.get_running_loop()

            def _handle_notify_task_done(task: asyncio.Task[None]) -> None:
                if task.cancelled():
                    return
                if exc := task.exception():
                    _LOGGER.debug("CUKTECH BLE notify handler failed: %s", exc, exc_info=True)

            def make_notify_callback(name: str) -> Callable[[Any, bytearray], None]:
                def notify_callback(sender: Any, data: bytearray, n: str = name) -> None:
                    def schedule_notify() -> None:
                        task = asyncio.create_task(on_notify(n, sender, data))
                        task.add_done_callback(_handle_notify_task_done)

                    loop.call_soon_threadsafe(schedule_notify)

                return notify_callback

            async def subscribe_name(name: str) -> None:
                await client.start_notify(chars[name], make_notify_callback(name))
                if name not in subscribed:
                    subscribed.append(name)
                await asyncio.sleep(0.05)

            async def recover_cmtp_path() -> bool:
                _LOGGER.warning("Trying CUKTECH CMTP recovery in current BLE session for %s", self._address)
                update_event.clear()
                with suppress(Exception):
                    await write_name("cmtp", bytes.fromhex("00000300"))

                try:
                    await asyncio.wait_for(update_event.wait(), timeout=1.0)
                    _LOGGER.info("CUKTECH CMTP recovered by poke in current BLE session for %s", self._address)
                    return True
                except asyncio.TimeoutError:
                    pass

                await asyncio.sleep(0.3)

                with suppress(Exception):
                    await client.stop_notify(chars["cmtp"])
                await asyncio.sleep(0.3)

                try:
                    await client.start_notify(chars["cmtp"], make_notify_callback("cmtp"))
                except Exception as exc:
                    _LOGGER.warning(
                        "Failed to restart CUKTECH CMTP notify for %s: %s",
                        self._address,
                        exc,
                        exc_info=True,
                    )
                    return False

                await asyncio.sleep(0.5)

                for attempt in range(3):
                    if stop_event.is_set() or disconnected_event.is_set() or not client.is_connected:
                        return False
                    update_event.clear()
                    await self._async_send_get_properties(send_vendor_frame, state)
                    if await self._async_wait_update_or_poke_cmtp(
                        write_name,
                        update_event,
                        first_timeout=5 + attempt * 2,
                        poke_timeout=1.5,
                        attempts=1,
                    ):
                        _LOGGER.info("CUKTECH CMTP recovered in current BLE session for %s", self._address)
                        return True
                    _LOGGER.debug(
                        "CUKTECH CMTP recovery attempt %s failed for %s",
                        attempt + 1,
                        self._address,
                    )
                    await asyncio.sleep(1.0)
                return False

            try:
                for name in ("cmtp", "vendor_1a", "vendor_1c", "avdtp"):
                    await subscribe_name(name)

                await self._async_login(
                    write_name,
                    state,
                    greeting_event,
                    rcv_rdy_event,
                    dev_random_event,
                    dev_info_event,
                    upnp_status_event,
                    lambda: subscribe_name("upnp"),
                )
                self._status_callback(True)
                _LOGGER.info("CUKTECH BLE login succeeded for %s", self._address)
                await self._async_send_get_properties(send_vendor_frame, state)

                while not stop_event.is_set() and not disconnected_event.is_set() and client.is_connected:
                    stop_task = asyncio.create_task(stop_event.wait())
                    control_task = asyncio.create_task(self._control_queue.get())
                    disconnected_task = asyncio.create_task(disconnected_event.wait())
                    done, pending = await asyncio.wait(
                        {stop_task, control_task, disconnected_task},
                        timeout=self._refresh_interval if self._refresh_interval > 0 else None,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                    for task in pending:
                        with suppress(asyncio.CancelledError):
                            await task
                    if stop_task in done or disconnected_task in done or stop_event.is_set() or disconnected_event.is_set() or not client.is_connected:
                        break
                    if control_task in done:
                        command = control_task.result()
                        _LOGGER.debug(
                            "Processing CUKTECH control for %s: %s marker=%s pre_control=%s pending_controls=%s",
                            self._address,
                            _format_property_debug(command.piid, command.value),
                            command.marker.hex(),
                            command.pre_control,
                            self._control_queue.qsize(),
                        )
                        update_event.clear()
                        await self._async_send_control_command(send_vendor_frame, state, command)
                        _LOGGER.info(
                            "CUKTECH control command sent for %s; waiting briefly for push update",
                            self._address,
                        )

                        try:
                            await asyncio.wait_for(update_event.wait(), timeout=0.8)
                            continue
                        except asyncio.TimeoutError:
                            pass

                        with suppress(Exception):
                            await write_name("cmtp", bytes.fromhex("00000300"))

                        try:
                            await asyncio.wait_for(update_event.wait(), timeout=1.2)
                            continue
                        except asyncio.TimeoutError:
                            pass

                        _LOGGER.info(
                            "No CUKTECH push after control for %s; requesting fresh properties",
                            self._address,
                        )
                        update_event.clear()
                        await self._async_send_get_properties(send_vendor_frame, state)

                        if await self._async_wait_update_or_poke_cmtp(write_name, update_event):
                            continue

                        _LOGGER.warning(
                            "No CUKTECH update after fast CMTP poke/get-property for %s; trying full in-session recovery",
                            self._address,
                        )
                        if await recover_cmtp_path():
                            continue
                        _LOGGER.warning(
                            "CUKTECH in-session recovery failed for %s; reconnecting BLE session",
                            self._address,
                        )
                        break
                    elif self._refresh_interval > 0:
                        await self._async_send_get_properties(send_vendor_frame, state)
            finally:
                for name in subscribed:
                    try:
                        await client.stop_notify(chars[name])
                    except Exception:
                        pass
                self._status_callback(False)
        finally:
            if client.is_connected:
                await client.disconnect()
            _LOGGER.info("Disconnected from CUKTECH BLE device %s", self._address)

    async def _async_read_firmware_version(self, client: BleakClient) -> None:
        try:
            value = await client.read_gatt_char(_char_by_uuid(client, FIRMWARE_VERSION_UUID))
        except Exception as exc:
            _LOGGER.debug("Failed to read CUKTECH firmware version: %s", exc, exc_info=True)
            return

        if version := _decode_firmware_version(bytes(value)):
            _LOGGER.info("Read CUKTECH firmware version for %s: %s", self._address, version)
            self._firmware_callback(version)

    async def _async_wait_update_or_poke_cmtp(
        self,
        write_name: WriteCallback,
        update_event: asyncio.Event,
        *,
        first_timeout: float = 1.5,
        poke_timeout: float = 1.5,
        attempts: int = 2,
    ) -> bool:
        for attempt in range(attempts):
            try:
                await asyncio.wait_for(
                    update_event.wait(),
                    timeout=first_timeout if attempt == 0 else poke_timeout,
                )
                return True
            except asyncio.TimeoutError:
                _LOGGER.debug(
                    "No CUKTECH update yet for %s; poking CMTP channel attempt=%s",
                    self._address,
                    attempt + 1,
                )
                with suppress(Exception):
                    await write_name("cmtp", bytes.fromhex("00000300"))
                await asyncio.sleep(0.15)

        try:
            await asyncio.wait_for(update_event.wait(), timeout=1.5)
            return True
        except asyncio.TimeoutError:
            return False

    async def _async_login(
        self,
        write_name: WriteCallback,
        state: dict[str, Any],
        greeting_event: asyncio.Event,
        rcv_rdy_event: asyncio.Event,
        dev_random_event: asyncio.Event,
        dev_info_event: asyncio.Event,
        upnp_status_event: asyncio.Event,
        subscribe_upnp: Callable[[], Awaitable[None]],
    ) -> None:
        app_random = secrets.token_bytes(16)

        await write_name("vendor_1c", bytes.fromhex("00"))
        await asyncio.sleep(0.2)
        await write_name("vendor_1c", bytes.fromhex("03"))
        await asyncio.sleep(0.2)
        await write_name("upnp", bytes.fromhex("a4"))

        deadline = monotonic() + 5
        while state["greeting_count"] < 2 and monotonic() < deadline:
            try:
                await asyncio.wait_for(greeting_event.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            greeting_event.clear()
        if state["greeting_count"] < 2:
            _LOGGER.debug(
                "CUKTECH BLE login continuing after %s AVDTP greeting frame(s)",
                state["greeting_count"],
            )

        await subscribe_upnp()
        await asyncio.sleep(0.2)

        await write_name("upnp", bytes.fromhex("24000000"))
        await write_name("avdtp", bytes.fromhex("0000000b0100"))
        try:
            await asyncio.wait_for(rcv_rdy_event.wait(), timeout=5)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Timed out waiting for AVDTP ready after random request") from exc
        await write_name("avdtp", bytes.fromhex("0100") + app_random)

        try:
            await asyncio.wait_for(dev_random_event.wait(), timeout=5)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Timed out waiting for device random") from exc
        try:
            await asyncio.wait_for(dev_info_event.wait(), timeout=5)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Timed out waiting for device HMAC info") from exc
        dev_random = state["dev_random"]
        dev_info = state["dev_info"]
        if dev_random is None or dev_info is None:
            raise RuntimeError("Missing device login random/info")

        await asyncio.sleep(0.25)
        app_info, expected_dev_info, keys = _derive_login(self._token, app_random, dev_random)
        if dev_info != expected_dev_info:
            raise CuktechAuthError("Mi auth token check failed: device HMAC mismatch")

        before = state["rcv_rdy_count"]
        rcv_rdy_event.clear()
        await write_name("avdtp", bytes.fromhex("0000000a0100"))
        while state["rcv_rdy_count"] <= before:
            try:
                await asyncio.wait_for(rcv_rdy_event.wait(), timeout=5)
            except asyncio.TimeoutError as exc:
                raise RuntimeError("Timed out waiting for AVDTP ready before auth HMAC") from exc
            rcv_rdy_event.clear()
        await write_name("avdtp", bytes.fromhex("0100") + app_info)
        try:
            await asyncio.wait_for(upnp_status_event.wait(), timeout=5)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Timed out waiting for UPNP login status") from exc
        if state["upnp_status"] != bytes.fromhex("21000000"):
            status = state["upnp_status"].hex() if state["upnp_status"] else None
            raise RuntimeError(f"Login failed: upnp status {status}")
        state["session_keys"] = keys

    async def _async_send_get_properties(
        self,
        send_vendor_frame: VendorFrameCallback,
        state: dict[str, Any],
    ) -> None:
        keys = state["session_keys"]
        if not state["initial_get_props_sent"]:
            frames = _build_get_prop_frames(keys)
            state["initial_get_props_sent"] = True
            state["next_counter"] = max(state["next_counter"], 8)
            _LOGGER.debug(
                "Sending initial CUKTECH MIOT get-property request for %s frames=%s",
                self._address,
                len(frames),
            )
        else:
            counter = state["next_counter"]
            state["next_counter"] += 1
            plaintext = bytes([0x33, 0x20, (counter + 2) & 0xFF, 0x00]) + MIOT_GET_PROPS_BODY
            frames = [_encrypt_vendor_frame(keys, counter, plaintext)]
            _LOGGER.debug(
                "Sending CUKTECH MIOT get-property request for %s counter=%s",
                self._address,
                counter,
            )
        for frame in frames:
            await send_vendor_frame(frame)

    async def _async_send_control_command(
        self,
        send_vendor_frame: VendorFrameCallback,
        state: dict[str, Any],
        command: ControlCommand,
    ) -> None:
        keys = state["session_keys"]
        if command.pre_control and not state["pre_control_sent"]:
            counter = state["next_counter"]
            state["next_counter"] += 1
            _LOGGER.debug("Sending CUKTECH pre-control frame for %s counter=%s", self._address, counter)
            frame = _encrypt_vendor_frame(keys, counter, _build_pre_control_plaintext(counter))
            await send_vendor_frame(frame)
            state["pre_control_sent"] = True

        counter = state["next_counter"]
        state["next_counter"] += 1
        frame = _encrypt_vendor_frame(
            keys,
            counter,
            _build_set_uint8_plaintext(counter, command.piid, command.marker, command.value),
        )
        _LOGGER.info(
            "Sending CUKTECH property control %s for %s",
            _format_property_debug(command.piid, command.value),
            self._address,
        )
        _LOGGER.debug(
            "CUKTECH control frame details for %s: counter=%s marker=%s payload_len=%s",
            self._address,
            counter,
            command.marker.hex(),
            len(frame),
        )
        await send_vendor_frame(frame)

    async def _async_send_vendor_frame(
        self,
        write_name: WriteCallback,
        state: dict[str, Any],
        frame: bytes,
    ) -> None:
        vendor_ready_event: asyncio.Event = state["vendor_ready_event"]
        vendor_done_event: asyncio.Event = state["vendor_done_event"]

        vendor_ready_event.clear()
        vendor_done_event.clear()
        frame_counter = int.from_bytes(frame[2:4], "little") if len(frame) >= 4 else None
        _LOGGER.debug(
            "Starting CUKTECH vendor transaction for %s counter=%s frame_len=%s",
            self._address,
            frame_counter,
            len(frame),
        )
        await write_name("vendor_1a", bytes.fromhex("000000000100"))

        try:
            await asyncio.wait_for(vendor_ready_event.wait(), timeout=1.5)
            _LOGGER.debug("CUKTECH vendor ready for %s counter=%s", self._address, frame_counter)
        except asyncio.TimeoutError:
            _LOGGER.debug(
                "Timed out waiting for CUKTECH vendor ready for %s; sending frame anyway",
                self._address,
            )

        await asyncio.sleep(0.05)
        vendor_done_event.clear()
        await write_name("vendor_1a", frame)

        try:
            await asyncio.wait_for(vendor_done_event.wait(), timeout=2.5)
            _LOGGER.debug("CUKTECH vendor done ACK for %s counter=%s", self._address, frame_counter)
        except asyncio.TimeoutError:
            _LOGGER.debug("Timed out waiting for CUKTECH vendor done ACK for %s", self._address)

        await asyncio.sleep(0.2)


async def async_validate_auth(hass: HomeAssistant, address: str, token_hex: str) -> str | None:
    """Connect to the charger and verify the Xiaomi Mi auth token once."""
    firmware_version: str | None = None

    def firmware_callback(version: str) -> None:
        nonlocal firmware_version
        firmware_version = version

    validator = Cuktech10UClient(
        hass=hass,
        address=address,
        token_hex=token_hex,
        refresh_interval=60,
        update_callback=lambda _update: None,
        status_callback=lambda _connected: None,
        firmware_callback=firmware_callback,
    )
    target = await validator._async_get_ble_device()
    rcv_rdy_event = asyncio.Event()
    dev_random_event = asyncio.Event()
    dev_info_event = asyncio.Event()
    upnp_status_event = asyncio.Event()
    greeting_event = asyncio.Event()
    state: dict[str, Any] = {
        "greeting_count": 0,
        "rcv_rdy_count": 0,
        "dev_random": None,
        "dev_info": None,
        "upnp_status": None,
        "session_keys": None,
        "parcel_kind": None,
        "parcel_expected_frames": 0,
        "parcel_data": bytearray(),
    }

    client = await establish_connection(BleakClient, target, address)
    _LOGGER.info("Connected to CUKTECH BLE device %s for config validation", address)
    try:
        chars = {name: _char_by_uuid(client, uuid) for name, uuid in UUIDS.items()}
        await validator._async_read_firmware_version(client)
        write_lock = asyncio.Lock()

        async def write_name(name: str, value: bytes) -> None:
            async with write_lock:
                await _async_write_char(client, chars[name], value, name)

        async def on_notify(name: str, _sender: Any, data: bytearray) -> None:
            value = bytes(data)
            _LOGGER.debug(
                "CUKTECH validation notify %s len=%s value=%s",
                name,
                len(value),
                _format_bytes(value),
            )
            if name == "avdtp" and value.startswith(bytes.fromhex("000004")):
                state["greeting_count"] += 1
                greeting_event.set()
                await write_name("avdtp", bytes.fromhex("000005") + value[3:])
            elif name == "avdtp" and value == bytes.fromhex("00000101"):
                state["rcv_rdy_count"] += 1
                rcv_rdy_event.set()
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000000d")) and len(value) >= 6:
                state["parcel_kind"] = 0x0D
                state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                state["parcel_data"] = bytearray()
                await write_name("avdtp", bytes.fromhex("00000101"))
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000000c")) and len(value) >= 6:
                state["parcel_kind"] = 0x0C
                state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                state["parcel_data"] = bytearray()
                await write_name("avdtp", bytes.fromhex("00000101"))
            elif (
                name == "avdtp"
                and state["parcel_kind"] is not None
                and len(value) >= 2
                and 1 <= value[0] <= state["parcel_expected_frames"]
            ):
                frame_no = value[0] + value[1] * 0x100
                state["parcel_data"].extend(value[2:])
                if frame_no == state["parcel_expected_frames"]:
                    if state["parcel_kind"] == 0x0D:
                        state["dev_random"] = bytes(state["parcel_data"])
                        dev_random_event.set()
                    elif state["parcel_kind"] == 0x0C:
                        state["dev_info"] = bytes(state["parcel_data"])
                        dev_info_event.set()
                    state["parcel_kind"] = None
                    state["parcel_expected_frames"] = 0
                    state["parcel_data"] = bytearray()
                    await write_name("avdtp", bytes.fromhex("00000300"))
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000020d")):
                state["dev_random"] = value[4:]
                dev_random_event.set()
                await write_name("avdtp", bytes.fromhex("00000300"))
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000020c")):
                state["dev_info"] = value[4:]
                dev_info_event.set()
                await write_name("avdtp", bytes.fromhex("00000300"))
            elif name == "upnp":
                state["upnp_status"] = value
                upnp_status_event.set()

        subscribed: list[str] = []
        loop = asyncio.get_running_loop()

        def handle_notify_task_done(task: asyncio.Task[None]) -> None:
            if task.cancelled():
                return
            if exc := task.exception():
                _LOGGER.debug("CUKTECH BLE validation notify handler failed: %s", exc, exc_info=True)

        async def subscribe_name(name: str) -> None:
            def notify_callback(sender: Any, data: bytearray, n: str = name) -> None:
                def schedule_notify() -> None:
                    task = asyncio.create_task(on_notify(n, sender, data))
                    task.add_done_callback(handle_notify_task_done)

                loop.call_soon_threadsafe(schedule_notify)

            await client.start_notify(chars[name], notify_callback)
            subscribed.append(name)
            await asyncio.sleep(0.05)

        try:
            for name in ("cmtp", "vendor_1a", "vendor_1c", "avdtp"):
                await subscribe_name(name)
            await validator._async_login(
                write_name,
                state,
                greeting_event,
                rcv_rdy_event,
                dev_random_event,
                dev_info_event,
                upnp_status_event,
                lambda: subscribe_name("upnp"),
            )
            _LOGGER.info("CUKTECH BLE config validation succeeded for %s", address)
            return firmware_version
        finally:
            for name in subscribed:
                with suppress(Exception):
                    await client.stop_notify(chars[name])
    finally:
        if client.is_connected:
            await client.disconnect()
        _LOGGER.info("Disconnected from CUKTECH BLE device %s after config validation", address)
