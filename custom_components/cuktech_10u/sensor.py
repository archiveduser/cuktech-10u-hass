from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorEntityDescription, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfElectricCurrent, UnitOfElectricPotential, UnitOfPower
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .client import CuktechUpdate
from .const import DOMAIN
from .coordinator import Cuktech10UCoordinator


@dataclass(frozen=True, kw_only=True)
class CuktechSensorEntityDescription(SensorEntityDescription):
    value_fn: Callable[[CuktechUpdate], float | int | str | None]
    attr_fn: Callable[[CuktechUpdate], dict[str, Any]] | None = None


def _port_value(port: str, field: str) -> Callable[[CuktechUpdate], float | int | str | None]:
    def _value(data: CuktechUpdate) -> float | int | str | None:
        reading = data.ports.get(port)
        return getattr(reading, field, None) if reading else None

    return _value


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
        }

    return _attrs


SENSOR_DESCRIPTIONS: tuple[CuktechSensorEntityDescription, ...] = (
    CuktechSensorEntityDescription(
        key="total_power",
        translation_key="total_power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        value_fn=lambda data: data.total_power_w,
    ),
)

for _port in ("c1", "c2", "c3", "a"):
    SENSOR_DESCRIPTIONS += (
        CuktechSensorEntityDescription(
            key=f"{_port}_power",
            translation_key=f"{_port}_power",
            device_class=SensorDeviceClass.POWER,
            native_unit_of_measurement=UnitOfPower.WATT,
            state_class=SensorStateClass.MEASUREMENT,
            suggested_display_precision=2,
            value_fn=_port_value(_port, "power_est_w"),
            attr_fn=_port_attrs(_port),
        ),
        CuktechSensorEntityDescription(
            key=f"{_port}_voltage",
            translation_key=f"{_port}_voltage",
            device_class=SensorDeviceClass.VOLTAGE,
            native_unit_of_measurement=UnitOfElectricPotential.VOLT,
            state_class=SensorStateClass.MEASUREMENT,
            suggested_display_precision=1,
            value_fn=_port_value(_port, "voltage_est_v"),
            attr_fn=_port_attrs(_port),
        ),
        CuktechSensorEntityDescription(
            key=f"{_port}_current",
            translation_key=f"{_port}_current",
            device_class=SensorDeviceClass.CURRENT,
            native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
            state_class=SensorStateClass.MEASUREMENT,
            suggested_display_precision=1,
            value_fn=_port_value(_port, "current_est_a"),
            attr_fn=_port_attrs(_port),
        ),
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: Cuktech10UCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(Cuktech10USensor(coordinator, description) for description in SENSOR_DESCRIPTIONS)


class Cuktech10USensor(CoordinatorEntity[Cuktech10UCoordinator], SensorEntity):
    entity_description: CuktechSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: Cuktech10UCoordinator,
        description: CuktechSensorEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}".replace(":", "").lower()

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def available(self) -> bool:
        return self.coordinator.data is not None

    @property
    def native_value(self) -> float | int | str | None:
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)

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
