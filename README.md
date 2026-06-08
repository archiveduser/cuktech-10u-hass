# CUKTECH 10 Ultra Home Assistant Integration

> This integration is provided for testing only. The project was generated with Codex and has been verified with my own CUKTECH 10 Ultra charger; compatibility with other firmware versions, accounts, regions, or Bluetooth adapters is not guaranteed.

Custom Home Assistant integration for the CUKTECH 10 Ultra / AD1204 charger.

## Installation

### HACS

1. In HACS, add this repository as a custom repository:

   ```text
   https://github.com/archiveduser/cuktech-10u-hass
   ```

2. Select category `Integration`.
3. Install `CUKTECH 10 Ultra`.
4. Restart Home Assistant.

### Manual

Copy `custom_components/cuktech_10u` into your Home Assistant `config/custom_components/` directory, then restart Home Assistant.

## Setup

1. Open `Settings -> Devices & services -> Add integration`.
2. Search for `CUKTECH 10 Ultra`.
3. Select the charger from the Bluetooth device list.
4. Enter the device token, or leave it empty to read it automatically from `xiaomi_home` or `xiaomi_miot` plugin configuration files.
5. Optionally set a device name.

## Entities

- Total power sensor
- C1/C2/C3/USB-A power, voltage, and current sensors
- C1/C2/C3/USB-A output switches
- USB-A low-current switch
- Charging scene selector
