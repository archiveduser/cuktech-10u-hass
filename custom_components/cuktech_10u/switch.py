from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, PORT_BITS
from .coordinator import Cuktech10UCoordinator


@dataclass(frozen=True, kw_only=True)
class CuktechSwitchEntityDescription(SwitchEntityDescription):
    kind: str
    port: str | None = None


SWITCH_DESCRIPTIONS: tuple[CuktechSwitchEntityDescription, ...] = (
    *tuple(
        CuktechSwitchEntityDescription(
            key=f"{port}_enabled",
            translation_key=f"{port}_enabled",
            kind="port",
            port=port,
        )
        for port in ("c1", "c2", "c3", "a")
    ),
    CuktechSwitchEntityDescription(
        key="usb_a_low_current",
        translation_key="usb_a_low_current",
        kind="usb_a_low_current",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: Cuktech10UCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(Cuktech10UPortSwitch(coordinator, description) for description in SWITCH_DESCRIPTIONS)


class Cuktech10UPortSwitch(CoordinatorEntity[Cuktech10UCoordinator], SwitchEntity):
    entity_description: CuktechSwitchEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: Cuktech10UCoordinator,
        description: CuktechSwitchEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}".replace(":", "").lower()

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def available(self) -> bool:
        return self.coordinator.connected and self.coordinator.data is not None

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        if self.entity_description.kind == "usb_a_low_current":
            return self.coordinator.is_usb_a_low_current_enabled()
        port = self.entity_description.port
        if port is None:
            return None
        mask = int(self.coordinator.data.properties.get("port_ctl", 0x0F)) & 0x0F
        return bool(mask & PORT_BITS[port])

    async def async_turn_on(self, **kwargs: Any) -> None:
        if self.entity_description.kind == "usb_a_low_current":
            await self.coordinator.async_set_usb_a_low_current(True)
            return
        if self.entity_description.port is not None:
            await self.coordinator.async_set_port_enabled(self.entity_description.port, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        if self.entity_description.kind == "usb_a_low_current":
            await self.coordinator.async_set_usb_a_low_current(False)
            return
        if self.entity_description.port is not None:
            await self.coordinator.async_set_port_enabled(self.entity_description.port, False)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.coordinator.data is None:
            return None
        port = self.entity_description.port
        reading = self.coordinator.data.ports.get(port) if port else None
        attrs: dict[str, Any] = {
            "connected": self.coordinator.connected,
            "last_update": self.coordinator.data.ts,
            "port_ctl": self.coordinator.data.properties.get("port_ctl"),
        }
        if self.entity_description.kind == "usb_a_low_current":
            attrs["usb_a_low_current"] = self.coordinator.data.properties.get("usb_a_low_current")
        if port:
            attrs["bit"] = PORT_BITS[port]
        if reading:
            attrs.update(
                {
                    "raw_hex": reading.raw_hex,
                    "bytes_le": reading.bytes_le,
                    "active": reading.active,
                    "state_byte": reading.state_byte,
                    "protocol_byte": reading.protocol_byte,
                    "power_est_w": reading.power_est_w,
                    "voltage_est_v": reading.voltage_est_v,
                    "current_est_a": reading.current_est_a,
                }
            )
        return attrs
