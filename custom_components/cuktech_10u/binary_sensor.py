from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .client import CuktechUpdate
from .const import DOMAIN
from .coordinator import Cuktech10UCoordinator


@dataclass(frozen=True, kw_only=True)
class CuktechBinarySensorEntityDescription(BinarySensorEntityDescription):
    is_on_fn: Callable[[CuktechUpdate], bool | None]
    attr_fn: Callable[[CuktechUpdate], dict[str, Any]] | None = None


def _port_supply_state(port: str) -> Callable[[CuktechUpdate], bool | None]:
    def _is_on(data: CuktechUpdate) -> bool | None:
        reading = data.ports.get(port)
        if not reading:
            return None
        return reading.active and reading.power_est_w > 0

    return _is_on


def _port_attrs(port: str) -> Callable[[CuktechUpdate], dict[str, Any]]:
    def _attrs(data: CuktechUpdate) -> dict[str, Any]:
        reading = data.ports.get(port)
        if not reading:
            return {}
        return {
            "raw_hex": reading.raw_hex,
            "bytes_le": reading.bytes_le,
            "active": reading.active,
            "state_byte": reading.state_byte,
            "protocol_byte": reading.protocol_byte,
            "power_est_w": reading.power_est_w,
            "voltage_est_v": reading.voltage_est_v,
            "current_est_a": reading.current_est_a,
        }

    return _attrs


BINARY_SENSOR_DESCRIPTIONS: tuple[CuktechBinarySensorEntityDescription, ...] = tuple(
    CuktechBinarySensorEntityDescription(
        key=f"{port}_supplying_power",
        translation_key=f"{port}_supplying_power",
        device_class=BinarySensorDeviceClass.POWER,
        is_on_fn=_port_supply_state(port),
        attr_fn=_port_attrs(port),
    )
    for port in ("c1", "c2", "c3", "a")
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: Cuktech10UCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        Cuktech10UBinarySensor(coordinator, description)
        for description in BINARY_SENSOR_DESCRIPTIONS
    )


class Cuktech10UBinarySensor(CoordinatorEntity[Cuktech10UCoordinator], BinarySensorEntity):
    entity_description: CuktechBinarySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: Cuktech10UCoordinator,
        description: CuktechBinarySensorEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}".replace(":", "").lower()

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def available(self) -> bool:
        return self.coordinator.available

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return self.entity_description.is_on_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.coordinator.data is None:
            return None
        attrs = (
            self.entity_description.attr_fn(self.coordinator.data)
            if self.entity_description.attr_fn is not None
            else {}
        )
        attrs["connected"] = self.coordinator.connected
        attrs["last_update"] = self.coordinator.data.ts
        return attrs
