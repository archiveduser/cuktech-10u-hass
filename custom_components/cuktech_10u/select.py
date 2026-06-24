from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, SCENE_MODE_OPTIONS, SCENE_MODE_PROPERTY, SCENE_MODE_VALUES
from .coordinator import Cuktech10UCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: Cuktech10UCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([Cuktech10USceneModeSelect(coordinator)])


class Cuktech10USceneModeSelect(CoordinatorEntity[Cuktech10UCoordinator], SelectEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "scene_mode"
    _attr_options = list(SCENE_MODE_OPTIONS)

    def __init__(self, coordinator: Cuktech10UCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.address}_scene_mode".replace(":", "").lower()

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def available(self) -> bool:
        return self.coordinator.available

    @property
    def current_option(self) -> str | None:
        if self.coordinator.data is None:
            return None
        value = self.coordinator.data.properties.get(SCENE_MODE_PROPERTY)
        if value is None:
            return None
        return SCENE_MODE_VALUES.get(int(value))

    async def async_select_option(self, option: str) -> None:
        await self.coordinator.async_set_scene_mode(option)
