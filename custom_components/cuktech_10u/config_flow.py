from __future__ import annotations

import asyncio
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components import bluetooth
from homeassistant.helpers import selector
from homeassistant.const import CONF_NAME
from bleak.exc import BleakError
from bleak_retry_connector import BleakOutOfConnectionSlotsError

from .client import CuktechAuthError, async_validate_auth
from .const import (
    CONF_ADDRESS,
    CONF_FIRMWARE_VERSION,
    CONF_REFRESH_INTERVAL,
    CONF_TOKEN,
    DEFAULT_REFRESH_INTERVAL,
    DOMAIN,
    FE95_SERVICE_UUID,
)
from .token_import import find_imported_tokens


LIKELY_NAME_PARTS = ("cuktech", "njcuk", "fitting", "ad1204")
MAC_HEX_RE = re.compile(r"^[0-9A-F]{12}$")


def _clean_address(value: str) -> str:
    return value.replace("-", ":").strip().upper()


def _validate_address(value: str) -> str:
    address = _clean_address(value)
    raw = address.replace(":", "")
    if not MAC_HEX_RE.fullmatch(raw):
        raise vol.Invalid("address must be a 12-character hex Bluetooth MAC")
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2))


def _clean_token(value: str) -> str:
    return value.replace(" ", "").replace(":", "").strip().lower()


def _validate_token(value: str) -> str:
    token = _clean_token(value)
    if len(token) != 24:
        raise vol.Invalid("token must be 12 bytes / 24 hex characters")
    try:
        bytes.fromhex(token)
    except ValueError as exc:
        raise vol.Invalid("token must be hex") from exc
    return token


def _looks_like_charger(info: bluetooth.BluetoothServiceInfoBleak) -> bool:
    service_uuids = {uuid.lower() for uuid in getattr(info, "service_uuids", [])}
    if FE95_SERVICE_UUID in service_uuids:
        return True
    name = (info.name or "").lower()
    return any(part in name for part in LIKELY_NAME_PARTS)


class Cuktech10UConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._discovered: dict[str, str] = {}

    async def _async_collect_discovered(self) -> None:
        await bluetooth.async_request_active_scan(self.hass)
        await asyncio.sleep(5)
        self._discovered = {
            info.address.upper(): info.name or info.address.upper()
            for info in bluetooth.async_discovered_service_info(self.hass, connectable=True)
            if _looks_like_charger(info)
        }

    async def _async_import_token_candidates(self, address: str) -> list[str]:
        storage_path = self.hass.config.path(".storage")
        candidates = await self.hass.async_add_executor_job(find_imported_tokens, storage_path, address)
        return list(dict.fromkeys(candidate.token for candidate in candidates))

    async def _async_validate_imported_token(self, address: str) -> tuple[str, str | None] | None:
        for token in await self._async_import_token_candidates(address):
            try:
                firmware_version = await async_validate_auth(self.hass, address, token)
            except CuktechAuthError:
                continue
            except (BleakOutOfConnectionSlotsError, BleakError, TimeoutError, RuntimeError):
                continue
            except Exception:
                continue
            return token, firmware_version
        return None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> config_entries.FlowResult:
        errors: dict[str, str] = {}

        if not self._discovered:
            await self._async_collect_discovered()

        address_options = {
            address: f"{name} ({address})" if name != address else address
            for address, name in sorted(self._discovered.items())
        }
        default_address = next(iter(address_options), None)

        if user_input is not None:
            try:
                address = _validate_address(user_input[CONF_ADDRESS])
            except vol.Invalid:
                errors[CONF_ADDRESS] = "invalid_address"
                address = ""
            token_input = user_input.get(CONF_TOKEN, "")
            token = ""
            firmware_version: str | None = None

            if errors:
                pass
            elif token_input:
                try:
                    token = _validate_token(token_input)
                except vol.Invalid:
                    errors[CONF_TOKEN] = "invalid_token"
                else:
                    try:
                        firmware_version = await async_validate_auth(self.hass, address, token)
                    except CuktechAuthError:
                        errors[CONF_TOKEN] = "invalid_auth"
                    except (BleakOutOfConnectionSlotsError, BleakError, TimeoutError, RuntimeError):
                        errors["base"] = "cannot_connect"
                    except Exception:
                        errors["base"] = "unknown"
            else:
                imported = await self._async_validate_imported_token(address)
                if imported is None:
                    errors[CONF_TOKEN] = "token_import_failed"
                else:
                    token, firmware_version = imported

            if not errors:
                await self.async_set_unique_id(address)
                self._abort_if_unique_id_configured()

                name = user_input.get(CONF_NAME) or self._discovered.get(address) or "CUKTECH 10 Ultra"
                data = {
                    CONF_ADDRESS: address,
                    CONF_TOKEN: token,
                }
                if firmware_version:
                    data[CONF_FIRMWARE_VERSION] = firmware_version
                return self.async_create_entry(
                    title=name,
                    data=data,
                    options={
                        CONF_REFRESH_INTERVAL: DEFAULT_REFRESH_INTERVAL,
                    },
                )

        address_field = (
            vol.Required(CONF_ADDRESS, default=default_address)
            if default_address
            else vol.Required(CONF_ADDRESS)
        )
        schema_fields: dict[Any, Any] = {
            address_field: selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[
                        {"value": address, "label": label}
                        for address, label in address_options.items()
                    ],
                    mode=selector.SelectSelectorMode.DROPDOWN,
                    custom_value=True,
                )
            ),
            vol.Optional(CONF_TOKEN): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(CONF_NAME): str,
        }

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema_fields),
            errors=errors,
        )
