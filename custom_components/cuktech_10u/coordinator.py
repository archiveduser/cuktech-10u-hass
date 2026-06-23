from __future__ import annotations

import asyncio
from dataclasses import replace
import logging
from time import monotonic

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .client import Cuktech10UClient, CuktechUpdate, PortReading
from .const import (
    CONF_ADDRESS,
    CONF_FIRMWARE_VERSION,
    CONF_REFRESH_INTERVAL,
    CONF_TOKEN,
    DEFAULT_REFRESH_INTERVAL,
    DEVICE_NAME,
    DOMAIN,
    PORT_BITS,
    SCENE_MODE_OPTIONS,
    USB_A_LOW_CURRENT_PROPERTY,
)

_LOGGER = logging.getLogger(__name__)
_PORT_MASK_EXPECTED_TTL = 15.0


class Cuktech10UCoordinator(DataUpdateCoordinator[CuktechUpdate]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry.entry_id}",
        )
        self.entry = entry
        self.address: str = entry.data[CONF_ADDRESS].upper()
        self.refresh_interval: int = int(entry.options.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL))
        self.connected = False
        self.firmware_version: str | None = entry.data.get(CONF_FIRMWARE_VERSION)
        self._stop_event: asyncio.Event | None = None
        self._task: asyncio.Task[None] | None = None
        self._expected_port_mask: int | None = None
        self._expected_port_mask_until = 0.0

        self._client = Cuktech10UClient(
            hass=hass,
            address=self.address,
            token_hex=entry.data[CONF_TOKEN],
            refresh_interval=self.refresh_interval,
            update_callback=self._async_handle_update,
            status_callback=self._async_handle_status,
            firmware_callback=self._async_handle_firmware_version,
        )

    async def async_start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        self._task = self.hass.async_create_background_task(
            self._client.async_run(self._stop_event),
            f"{DOMAIN} BLE client {self.address}",
        )
        self._task.add_done_callback(self._handle_task_done)

    async def async_stop(self) -> None:
        if self._stop_event:
            self._stop_event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self._stop_event = None

    async def async_set_port_enabled(self, port: str, enabled: bool) -> None:
        bit = PORT_BITS[port]
        current_mask = self._current_port_mask()
        new_mask = (current_mask | bit) if enabled else (current_mask & ~bit)
        _LOGGER.debug(
            "Setting CUKTECH port %s enabled=%s current_mask=0x%x new_mask=0x%x",
            port,
            enabled,
            current_mask,
            new_mask,
        )
        self._expected_port_mask = new_mask
        self._expected_port_mask_until = monotonic() + _PORT_MASK_EXPECTED_TTL
        self._async_set_optimistic_property("port_ctl", new_mask)
        await self._client.async_set_port_mask(new_mask)

    async def async_set_usb_a_low_current(self, enabled: bool) -> None:
        await self._client.async_set_uint8_property(15, 1 if enabled else 0, marker=bytes.fromhex("0100"))

    async def async_set_scene_mode(self, option: str) -> None:
        await self._client.async_set_uint8_property(5, SCENE_MODE_OPTIONS[option])

    def is_usb_a_low_current_enabled(self) -> bool | None:
        if self.data is None or USB_A_LOW_CURRENT_PROPERTY not in self.data.properties:
            return None
        return bool(self.data.properties[USB_A_LOW_CURRENT_PROPERTY])

    def _current_port_mask(self) -> int:
        if self._expected_port_mask is not None and monotonic() < self._expected_port_mask_until:
            return self._expected_port_mask
        current_mask = 0x0F
        if self.data is not None:
            current_mask = int(self.data.properties.get("port_ctl", current_mask)) & 0x0F
        return current_mask

    @callback
    def _async_set_optimistic_property(self, name: str, value: int) -> None:
        if self.data is None:
            return
        properties = dict(self.data.properties)
        properties[name] = value
        self.async_set_updated_data(replace(self.data, properties=properties))

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.address)},
            connections={(CONNECTION_BLUETOOTH, self.address)},
            manufacturer="CUKTECH",
            model="10 Ultra",
            name=self.entry.title or DEVICE_NAME,
            sw_version=self.firmware_version,
        )

    @callback
    def _async_handle_status(self, connected: bool) -> None:
        self.connected = connected
        self.async_update_listeners()

    @callback
    def _async_handle_firmware_version(self, firmware_version: str) -> None:
        if self.firmware_version == firmware_version:
            return
        self.firmware_version = firmware_version
        self.async_update_listeners()

    @callback
    def _async_handle_update(self, update: CuktechUpdate) -> None:
        if self.data is None:
            self.async_set_updated_data(update)
            return

        ports: dict[str, PortReading] = dict(self.data.ports)
        ports.update(update.ports)
        properties = dict(self.data.properties)
        update_properties = dict(update.properties)
        if "port_ctl" in update_properties:
            incoming_mask = int(update_properties["port_ctl"]) & 0x0F
            expected_mask = self._expected_port_mask
            expected_active = expected_mask is not None and monotonic() < self._expected_port_mask_until
            _LOGGER.debug(
                "Received CUKTECH port_ctl update incoming=0x%x expected=%s active=%s",
                incoming_mask,
                f"0x{expected_mask:x}" if expected_mask is not None else None,
                expected_active,
            )
            if expected_active and incoming_mask == 0 and expected_mask != 0:
                _LOGGER.debug(
                    "Ignoring CUKTECH port_ctl=0 while waiting for expected port mask 0x%x",
                    expected_mask,
                )
                update_properties.pop("port_ctl")
            else:
                if expected_mask is not None:
                    self._expected_port_mask = None
                    self._expected_port_mask_until = 0.0
                update_properties["port_ctl"] = incoming_mask
        properties.update(update_properties)
        total = round(sum(port.power_est_w for port in ports.values()), 3)
        merged = replace(
            update,
            ports=ports,
            properties=properties,
            total_power_w=total,
        )
        self.async_set_updated_data(merged)

    async def _async_update_data(self) -> CuktechUpdate:
        if self.data is None:
            raise RuntimeError("No CUKTECH data received yet")
        return self.data

    @callback
    def _handle_task_done(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        if exc := task.exception():
            _LOGGER.error(
                "CUKTECH background task stopped unexpectedly: %s",
                exc,
                exc_info=(type(exc), exc, exc.__traceback__),
            )
