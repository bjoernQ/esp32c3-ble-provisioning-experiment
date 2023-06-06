# ESP32-C3 bare-metal WiFi Provisioning via BLE Experiment

See [Unified Provisioning](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/provisioning/provisioning.html)

## Build and Flash

```
cargo build --release
espflash flash --monitor  --partition-table partitions.csv --erase-parts nvs target\riscv32imc-unknown-none-elf\release\esp32c3_ble_provisioning
```

## TODO

- [ ] really implement the protocol (but should already work with the [Android app](https://play.google.com/store/apps/details?id=com.espressif.provble))
- [ ] implement `security1`
