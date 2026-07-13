from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from math import isfinite
from time import monotonic
from typing import Any

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfPower,
)
from homeassistant.core import HomeAssistant, callback
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


ENERGY_DESCRIPTIONS: tuple[CuktechSensorEntityDescription, ...] = (
    CuktechSensorEntityDescription(
        key="total_energy",
        translation_key="total_energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL,
        suggested_display_precision=3,
        value_fn=lambda data: data.total_power_w,
    ),
)

for _port in ("c1", "c2", "c3", "a"):
    ENERGY_DESCRIPTIONS += (
        CuktechSensorEntityDescription(
            key=f"{_port}_energy",
            translation_key=f"{_port}_energy",
            device_class=SensorDeviceClass.ENERGY,
            native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
            state_class=SensorStateClass.TOTAL,
            suggested_display_precision=3,
            value_fn=_port_value(_port, "power_est_w"),
        ),
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: Cuktech10UCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            Cuktech10USensor(coordinator, description)
            for description in SENSOR_DESCRIPTIONS
        ]
        + [
            Cuktech10UEnergySensor(coordinator, description)
            for description in ENERGY_DESCRIPTIONS
        ]
    )


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
        self._attr_unique_id = f"{coordinator.address}_{description.key}".replace(
            ":", ""
        ).lower()

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def available(self) -> bool:
        return self.coordinator.available

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


class Cuktech10UEnergySensor(CoordinatorEntity[Cuktech10UCoordinator], RestoreSensor):
    """Estimated cumulative output energy derived from charger power readings."""

    entity_description: CuktechSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: Cuktech10UCoordinator,
        description: CuktechSensorEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}".replace(
            ":", ""
        ).lower()
        self._energy_kwh: float | None = None
        self._last_power_w: float | None = None
        self._last_sample_monotonic: float | None = None
        self._last_update_ts: str | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()

        if (last_sensor_data := await self.async_get_last_sensor_data()) is not None:
            try:
                restored_energy = float(last_sensor_data.native_value)
            except (TypeError, ValueError):
                pass
            else:
                if isfinite(restored_energy) and restored_energy >= 0:
                    self._energy_kwh = restored_energy

        self._seed_sample()

    async def async_will_remove_from_hass(self) -> None:
        if self.coordinator.connected:
            self._finalize_sample(monotonic())
        await super().async_will_remove_from_hass()

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def available(self) -> bool:
        return self._energy_kwh is not None

    @property
    def native_value(self) -> float | None:
        if self._energy_kwh is None:
            return None
        return round(self._energy_kwh, 6)

    @callback
    def _handle_coordinator_update(self) -> None:
        if not self.coordinator.connected:
            self._finalize_sample(monotonic())
        elif (
            self.coordinator.data is not None
            and self.coordinator.data.ts != self._last_update_ts
        ):
            now = monotonic()
            power_w = self._current_power_w()
            if (
                power_w is not None
                and self._last_power_w is not None
                and self._last_sample_monotonic is not None
            ):
                elapsed_seconds = max(0.0, now - self._last_sample_monotonic)
                average_power_w = (self._last_power_w + power_w) / 2
                self._energy_kwh = (self._energy_kwh or 0.0) + (
                    average_power_w * elapsed_seconds / 3_600_000
                )
            self._set_sample(power_w, now)

        super()._handle_coordinator_update()

    def _finalize_sample(self, sample_time: float) -> None:
        if self._last_power_w is not None and self._last_sample_monotonic is not None:
            elapsed_seconds = max(0.0, sample_time - self._last_sample_monotonic)
            self._energy_kwh = (self._energy_kwh or 0.0) + (
                self._last_power_w * elapsed_seconds / 3_600_000
            )
        self._clear_sample()

    def _seed_sample(self) -> None:
        if not self.coordinator.available or self.coordinator.data is None:
            return
        self._set_sample(self._current_power_w(), monotonic())

    def _set_sample(self, power_w: float | None, sample_time: float) -> None:
        if power_w is not None and self._energy_kwh is None:
            self._energy_kwh = 0.0
        self._last_power_w = power_w
        self._last_sample_monotonic = sample_time if power_w is not None else None
        self._last_update_ts = (
            self.coordinator.data.ts if self.coordinator.data is not None else None
        )

    def _clear_sample(self) -> None:
        self._last_power_w = None
        self._last_sample_monotonic = None
        self._last_update_ts = (
            self.coordinator.data.ts if self.coordinator.data is not None else None
        )

    def _current_power_w(self) -> float | None:
        if self.coordinator.data is None:
            return None
        value = self.entity_description.value_fn(self.coordinator.data)
        if not isinstance(value, int | float):
            return None
        power_w = float(value)
        return max(0.0, power_w) if isfinite(power_w) else None
