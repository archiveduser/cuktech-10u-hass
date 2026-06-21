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

UpdateCallback = Callable[["CuktechUpdate"], None]
StatusCallback = Callable[[bool], None]
FirmwareCallback = Callable[[str], None]


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


async def _async_write_char(client: BleakClient, char: Any, value: bytes) -> None:
    response = "write" in (getattr(char, "properties", None) or ())
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
        pending_writes: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()
        rcv_rdy_event = asyncio.Event()
        dev_random_event = asyncio.Event()
        dev_info_event = asyncio.Event()
        upnp_status_event = asyncio.Event()
        greeting_event = asyncio.Event()
        disconnected_event = asyncio.Event()
        update_event = asyncio.Event()

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

            async def write_name(name: str, value: bytes) -> None:
                await _async_write_char(client, chars[name], value)

            async def writer_task() -> None:
                while True:
                    item = await pending_writes.get()
                    if item is None:
                        return
                    await write_name(*item)

            writer = asyncio.create_task(writer_task())

            async def on_notify(name: str, _sender: Any, data: bytearray) -> None:
                value = bytes(data)
                if name == "avdtp" and value.startswith(bytes.fromhex("000004")):
                    state["greeting_count"] += 1
                    greeting_event.set()
                    await pending_writes.put(("avdtp", bytes.fromhex("000005") + value[3:]))
                elif name == "avdtp" and value == bytes.fromhex("00000101"):
                    state["rcv_rdy_count"] += 1
                    rcv_rdy_event.set()
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000000d")) and len(value) >= 6:
                    state["parcel_kind"] = 0x0D
                    state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                    state["parcel_data"] = bytearray()
                    await pending_writes.put(("avdtp", bytes.fromhex("00000101")))
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000000c")) and len(value) >= 6:
                    state["parcel_kind"] = 0x0C
                    state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                    state["parcel_data"] = bytearray()
                    await pending_writes.put(("avdtp", bytes.fromhex("00000101")))
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
                        await pending_writes.put(("avdtp", bytes.fromhex("00000300")))
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000020d")):
                    state["dev_random"] = value[4:]
                    dev_random_event.set()
                    await pending_writes.put(("avdtp", bytes.fromhex("00000300")))
                elif name == "avdtp" and value.startswith(bytes.fromhex("0000020c")):
                    state["dev_info"] = value[4:]
                    dev_info_event.set()
                    await pending_writes.put(("avdtp", bytes.fromhex("00000300")))
                elif name == "upnp":
                    state["upnp_status"] = value
                    upnp_status_event.set()
                elif name == "cmtp" and value.startswith(bytes.fromhex("000002")):
                    await pending_writes.put(("cmtp", bytes.fromhex("00000300")))
                    keys = state["session_keys"]
                    if keys and len(value) > 10:
                        counter = int.from_bytes(value[4:6], "little")
                        try:
                            plaintext = _decrypt_session_payload(keys["dev_key"], keys["dev_iv"], counter, value[6:])
                        except Exception as exc:
                            _LOGGER.debug("Failed to decrypt CMTP payload: %s", exc, exc_info=True)
                            return
                        if update := parse_miot_payload(self._address, plaintext):
                            _LOGGER.info(
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

            async def subscribe_name(name: str) -> None:
                def notify_callback(sender: Any, data: bytearray, n: str = name) -> None:
                    def schedule_notify() -> None:
                        task = asyncio.create_task(on_notify(n, sender, data))
                        task.add_done_callback(_handle_notify_task_done)

                    loop.call_soon_threadsafe(schedule_notify)

                await client.start_notify(chars[name], notify_callback)
                subscribed.append(name)
                await asyncio.sleep(0.05)

            try:
                for name in ("cmtp", "vendor_1a", "vendor_1c", "avdtp"):
                    await subscribe_name(name)

                await self._async_login(
                    client,
                    chars,
                    pending_writes,
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
                await self._async_send_get_properties(pending_writes, state)

                while not stop_event.is_set() and not disconnected_event.is_set() and client.is_connected:
                    stop_task = asyncio.create_task(stop_event.wait())
                    control_task = asyncio.create_task(self._control_queue.get())
                    done, pending = await asyncio.wait(
                        {stop_task, control_task},
                        timeout=self._refresh_interval if self._refresh_interval > 0 else None,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                    for task in pending:
                        with suppress(asyncio.CancelledError):
                            await task
                    if stop_task in done or stop_event.is_set() or disconnected_event.is_set() or not client.is_connected:
                        break
                    if control_task in done:
                        command = control_task.result()
                        update_event.clear()
                        await self._async_send_control_command(pending_writes, state, command)
                        _LOGGER.info(
                            "CUKTECH control command sent for %s; waiting for device push update",
                            self._address,
                        )
                        try:
                            await asyncio.wait_for(update_event.wait(), timeout=4)
                        except asyncio.TimeoutError:
                            _LOGGER.warning(
                                "No CUKTECH push update after control for %s; reconnecting BLE session",
                                self._address,
                            )
                            break
                    elif self._refresh_interval > 0:
                        await self._async_send_get_properties(pending_writes, state)
            finally:
                await pending_writes.put(None)
                with suppress(Exception):
                    await writer
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

    async def _async_login(
        self,
        client: BleakClient,
        chars: dict[str, Any],
        pending_writes: asyncio.Queue[tuple[str, bytes] | None],
        state: dict[str, Any],
        greeting_event: asyncio.Event,
        rcv_rdy_event: asyncio.Event,
        dev_random_event: asyncio.Event,
        dev_info_event: asyncio.Event,
        upnp_status_event: asyncio.Event,
        subscribe_upnp: Callable[[], Awaitable[None]],
    ) -> None:
        async def write_name(name: str, value: bytes) -> None:
            await _async_write_char(client, chars[name], value)

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
        pending_writes: asyncio.Queue[tuple[str, bytes] | None],
        state: dict[str, Any],
    ) -> None:
        keys = state["session_keys"]
        _LOGGER.info("Sending encrypted CUKTECH MIOT get-property request for %s", self._address)
        if not state["initial_get_props_sent"]:
            frames = _build_get_prop_frames(keys)
            state["initial_get_props_sent"] = True
            state["next_counter"] = max(state["next_counter"], 8)
        else:
            counter = state["next_counter"]
            state["next_counter"] += 1
            plaintext = bytes([0x33, 0x20, (counter + 2) & 0xFF, 0x00]) + MIOT_GET_PROPS_BODY
            frames = [_encrypt_vendor_frame(keys, counter, plaintext)]
        for frame in frames:
            await self._async_send_vendor_frame(pending_writes, frame)

    async def _async_send_control_command(
        self,
        pending_writes: asyncio.Queue[tuple[str, bytes] | None],
        state: dict[str, Any],
        command: ControlCommand,
    ) -> None:
        keys = state["session_keys"]
        if command.pre_control and not state["pre_control_sent"]:
            counter = state["next_counter"]
            state["next_counter"] += 1
            frame = _encrypt_vendor_frame(keys, counter, _build_pre_control_plaintext(counter))
            await self._async_send_vendor_frame(pending_writes, frame)
            state["pre_control_sent"] = True

        counter = state["next_counter"]
        state["next_counter"] += 1
        frame = _encrypt_vendor_frame(
            keys,
            counter,
            _build_set_uint8_plaintext(counter, command.piid, command.marker, command.value),
        )
        _LOGGER.info(
            "Sending CUKTECH property control piid=%s value=%s for %s",
            command.piid,
            command.value,
            self._address,
        )
        await self._async_send_vendor_frame(pending_writes, frame)

    async def _async_send_vendor_frame(
        self,
        pending_writes: asyncio.Queue[tuple[str, bytes] | None],
        frame: bytes,
    ) -> None:
        await pending_writes.put(("vendor_1a", bytes.fromhex("000000000100")))
        await asyncio.sleep(0.25)
        await pending_writes.put(("vendor_1a", frame))
        await asyncio.sleep(0.5)


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
    pending_writes: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()
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

        async def write_name(name: str, value: bytes) -> None:
            await _async_write_char(client, chars[name], value)

        async def writer_task() -> None:
            while True:
                item = await pending_writes.get()
                if item is None:
                    return
                await write_name(*item)

        writer = asyncio.create_task(writer_task())

        async def on_notify(name: str, _sender: Any, data: bytearray) -> None:
            value = bytes(data)
            if name == "avdtp" and value.startswith(bytes.fromhex("000004")):
                state["greeting_count"] += 1
                greeting_event.set()
                await pending_writes.put(("avdtp", bytes.fromhex("000005") + value[3:]))
            elif name == "avdtp" and value == bytes.fromhex("00000101"):
                state["rcv_rdy_count"] += 1
                rcv_rdy_event.set()
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000000d")) and len(value) >= 6:
                state["parcel_kind"] = 0x0D
                state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                state["parcel_data"] = bytearray()
                await pending_writes.put(("avdtp", bytes.fromhex("00000101")))
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000000c")) and len(value) >= 6:
                state["parcel_kind"] = 0x0C
                state["parcel_expected_frames"] = value[4] + value[5] * 0x100
                state["parcel_data"] = bytearray()
                await pending_writes.put(("avdtp", bytes.fromhex("00000101")))
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
                    await pending_writes.put(("avdtp", bytes.fromhex("00000300")))
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000020d")):
                state["dev_random"] = value[4:]
                dev_random_event.set()
                await pending_writes.put(("avdtp", bytes.fromhex("00000300")))
            elif name == "avdtp" and value.startswith(bytes.fromhex("0000020c")):
                state["dev_info"] = value[4:]
                dev_info_event.set()
                await pending_writes.put(("avdtp", bytes.fromhex("00000300")))
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
                client,
                chars,
                pending_writes,
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
            await pending_writes.put(None)
            with suppress(Exception):
                await writer
            for name in subscribed:
                with suppress(Exception):
                    await client.stop_notify(chars[name])
    finally:
        if client.is_connected:
            await client.disconnect()
        _LOGGER.info("Disconnected from CUKTECH BLE device %s after config validation", address)
