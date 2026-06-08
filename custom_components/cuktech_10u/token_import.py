from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterator

AD1204_MODEL = "njcuk.fitting.ad1204"

_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{24}$")


@dataclass(frozen=True)
class ImportedToken:
    source: str
    name: str
    token: str
    path: str
    did: str | None = None
    mac: str | None = None

    @property
    def label(self) -> str:
        parts = [self.source, self.name, self.token]
        if self.mac:
            parts.insert(2, self.mac)
        return " | ".join(parts)


def _clean_address(value: str | None) -> str | None:
    if not value:
        return None
    return value.replace("-", ":").strip().upper()


def _clean_token(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.replace(" ", "").replace(":", "").strip().lower()
    return token if _TOKEN_RE.fullmatch(token) else None


def _read_json_like(path: Path) -> Any:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore").lstrip("\ufeff")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        obj, _idx = decoder.raw_decode(text)
        return obj


def _iter_dicts(obj: Any) -> Iterator[dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _iter_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_dicts(value)


def _device_name(device: dict[str, Any]) -> str:
    name = device.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    did = device.get("did")
    if isinstance(did, str) and did.strip():
        return did.strip()
    return AD1204_MODEL


def _xiaomi_miot_candidates(storage_path: Path, address: str | None) -> list[ImportedToken]:
    candidates: list[ImportedToken] = []
    for path in sorted((storage_path / "xiaomi_miot").glob("devices-*-*.json")):
        try:
            obj = _read_json_like(path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        for device in _iter_dicts(obj):
            if device.get("model") != AD1204_MODEL:
                continue
            mac = _clean_address(device.get("mac"))
            if address and mac != address:
                continue
            token = _clean_token(device.get("token"))
            if not token:
                continue
            did = device.get("did")
            candidates.append(
                ImportedToken(
                    source="hass-xiaomi-miot",
                    name=_device_name(device),
                    token=token,
                    mac=mac,
                    did=did if isinstance(did, str) else None,
                    path=str(path),
                )
            )
    return candidates


def _xiaomi_home_candidates(storage_path: Path) -> list[ImportedToken]:
    candidates: list[ImportedToken] = []
    for path in sorted((storage_path / "xiaomi_home" / "miot_devices").glob("*.dict")):
        try:
            obj = _read_json_like(path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        for device in _iter_dicts(obj):
            if device.get("model") != AD1204_MODEL:
                continue
            token = _clean_token(device.get("token"))
            if not token:
                continue
            did = device.get("did")
            candidates.append(
                ImportedToken(
                    source="ha_xiaomi_home",
                    name=_device_name(device),
                    token=token,
                    did=did if isinstance(did, str) else None,
                    path=str(path),
                )
            )
    return candidates


def find_imported_tokens(storage_path: str, address: str | None = None) -> list[ImportedToken]:
    storage = Path(storage_path)
    clean_address = _clean_address(address)
    candidates = _xiaomi_miot_candidates(storage, clean_address)
    candidates.extend(_xiaomi_home_candidates(storage))

    unique: dict[str, ImportedToken] = {}
    for candidate in candidates:
        unique.setdefault(candidate.token, candidate)
    return list(unique.values())


def find_imported_devices(storage_path: str) -> list[ImportedToken]:
    storage = Path(storage_path)
    candidates = _xiaomi_miot_candidates(storage, None)
    candidates.extend(candidate for candidate in _xiaomi_home_candidates(storage) if candidate.mac)

    unique: dict[str, ImportedToken] = {}
    for candidate in candidates:
        if candidate.mac:
            unique.setdefault(candidate.mac, candidate)
    return list(unique.values())
