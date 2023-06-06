#![no_std]
#![no_main]

use core::cell::RefCell;

use bleps::{
    ad_structure::{
        create_advertising_data, AdStructure, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE,
    },
    attribute_server::{AttributeServer, WorkResult},
    gatt, Ble, HciConnector,
};
use embedded_io::blocking::*;
use embedded_storage::ReadStorage;
use embedded_storage::Storage;
use embedded_svc::{
    ipv4::Interface,
    wifi::{ClientConfiguration, Configuration, Wifi},
};
use esp_backtrace as _;
use esp_println::{print, println};
use esp_storage::FlashStorage;
use esp_wifi::{
    ble::controller::BleConnector,
    current_millis, initialize,
    wifi::{utils::create_network_interface, WifiMode},
    wifi_interface::WifiStack,
    EspWifiInitFor, EspWifiInitialization,
};
use hal::{
    clock::{ClockControl, CpuClock},
    peripherals::Peripherals,
    prelude::*,
    radio::Bluetooth,
    systimer::SystemTimer,
    timer::TimerGroup,
    Rng, Rtc,
};
use heapless::String;
use smoltcp::{
    iface::SocketStorage,
    wire::{IpAddress, Ipv4Address},
};

#[entry]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz).freeze();

    // Disable the RTC and TIMG watchdog timers
    let mut rtc = Rtc::new(peripherals.RTC_CNTL);
    let timer_group0 = TimerGroup::new(
        peripherals.TIMG0,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt0 = timer_group0.wdt;
    let timer_group1 = TimerGroup::new(
        peripherals.TIMG1,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt1 = timer_group1.wdt;
    rtc.swd.disable();
    rtc.rwdt.disable();
    wdt0.disable();
    wdt1.disable();

    let systimer = SystemTimer::new(peripherals.SYSTIMER);

    let mut flash_buffer = [0u8; 64];
    let mut flash = FlashStorage::new();
    let flash_addr = 0x9000;

    flash.read(flash_addr, &mut flash_buffer).unwrap();

    if flash_buffer[0] != b'p' {
        println!("We are unprovisioned");

        let init = initialize(
            EspWifiInitFor::Ble,
            systimer.alarm0,
            Rng::new(peripherals.RNG),
            system.radio_clock_control,
            &clocks,
        )
        .unwrap();

        let (_, mut bluetooth) = peripherals.RADIO.split();
        let (ssid, password) = ble_provisioning(&init, &mut bluetooth);

        flash_buffer[0] = b'p';
        flash_buffer[1] = ssid.len() as u8;
        flash_buffer[2..][..ssid.len()].copy_from_slice(ssid.as_bytes());
        flash_buffer[32] = password.len() as u8;
        flash_buffer[33..][..password.len()].copy_from_slice(password.as_bytes());
        flash.write(flash_addr, &flash_buffer).unwrap();

        hal::reset::software_reset();
    } else {
        println!("We are provisioned");

        let mut ssid: String<32> = String::new();
        let mut password: String<32> = String::new();
        ssid.push_str(
            core::str::from_utf8(&flash_buffer[2..][..flash_buffer[1] as usize]).unwrap(),
        )
        .unwrap();
        password
            .push_str(
                core::str::from_utf8(&flash_buffer[33..][..flash_buffer[32] as usize]).unwrap(),
            )
            .unwrap();

        let init = initialize(
            EspWifiInitFor::Wifi,
            systimer.alarm0,
            Rng::new(peripherals.RNG),
            system.radio_clock_control,
            &clocks,
        )
        .unwrap();

        let (mut wifi, _) = peripherals.RADIO.split();
        provisioned(
            &init,
            unsafe { core::mem::transmute(&mut wifi) },
            &ssid,
            &password,
        );
    }

    loop {}
}

fn ble_provisioning(
    init: &EspWifiInitialization,
    bluetooth: &mut Bluetooth,
) -> (String<32>, String<32>) {
    let connector = BleConnector::new(init, bluetooth);
    let hci = HciConnector::new(connector, current_millis);

    loop {
        let mut ble = Ble::new(&hci);
        ble.init().unwrap();
        ble.cmd_set_le_advertising_parameters().unwrap();
        ble.cmd_set_le_advertising_data(
            create_advertising_data(&[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::ServiceUuids128(&[Uuid::Uuid128([
                    0xb4, 0xdf, 0x5a, 0x1c, 0x3f, 0x6b, 0xf4, 0xbf, 0xea, 0x4a, 0x82, 0x03, 0x04,
                    0x90, 0x1a, 0x02,
                ])]),
                AdStructure::CompleteLocalName("ESP32-C3"),
            ])
            .unwrap(),
        )
        .unwrap();
        ble.cmd_set_le_advertise_enable(true).unwrap();

        let prov_config_idx = RefCell::new(-1isize);
        let prov_config_data = RefCell::new([[0u8; 64]; 5]);

        let mut read_prov_scan = |_offset: usize, _buf: &mut [u8]| {
            // TODO implement this
            Ok(0)
        };
        let mut write_prov_scan = |_offset: usize, _buf: &[u8]| {
            // TODO implement this
        };

        let mut read_session = |_offset: usize, _buf: &mut [u8]| {
            // TODO implement this
            Ok(0)
        };
        let mut write_session = |_offset: usize, _buf: &[u8]| {
            // TODO implement this
        };

        let mut read_config = |_offset: usize, _buf: &mut [u8]| {
            // TODO implement this
            Ok(0)
        };
        let mut write_config = |offset: usize, buf: &[u8]| {
            let mut prov_config_idx = prov_config_idx.borrow_mut();
            let mut prov_config_data = prov_config_data.borrow_mut();

            if offset == 0 {
                *prov_config_idx += 1;
            }

            prov_config_data[*prov_config_idx as usize][offset..][..buf.len()].copy_from_slice(buf);
        };

        let mut read_version = |_offset: usize, _buf: &mut [u8]| {
            // TODO implement this
            Ok(0)
        };
        let mut write_version = |_offset: usize, _buf: &[u8]| {
            // TODO implement this
        };

        let mut read_cloud_user_assoc = |_offset: usize, _buf: &mut [u8]| {
            // TODO implement this
            Ok(0)
        };
        let mut write_cloud_user_assoc = |_offset: usize, _buf: &[u8]| {
            // TODO implement this
        };

        gatt!([service {
            uuid: "021a9004-0382-4aea-bff4-6b3f1c5adfb4",
            characteristics: [
                characteristic {
                    uuid: "021aff50-0382-4aea-bff4-6b3f1c5adfb4",
                    read: read_prov_scan,
                    write: write_prov_scan,
                    description: "prov-scan",
                },
                characteristic {
                    uuid: "021aff51-0382-4aea-bff4-6b3f1c5adfb4",
                    read: read_session,
                    write: write_session,
                    description: "prov-session",
                },
                characteristic {
                    uuid: "021aff52-0382-4aea-bff4-6b3f1c5adfb4",
                    read: read_config,
                    write: write_config,
                    description: "prov-config",
                },
                characteristic {
                    uuid: "021aff53-0382-4aea-bff4-6b3f1c5adfb4",
                    read: read_version,
                    write: write_version,
                    description: "proto-ver",
                },
                characteristic {
                    uuid: "021aff54-0382-4aea-bff4-6b3f1c5adfb4",
                    read: read_cloud_user_assoc,
                    write: write_cloud_user_assoc,
                    description: "cloud_user_assoc",
                },
            ],
        },]);

        let mut srv = AttributeServer::new(&mut ble, &mut gatt_attributes);
        loop {
            match srv.do_work_with_notification(None) {
                Ok(res) => {
                    if let WorkResult::GotDisconnected = res {
                        let prov_config_len = (*prov_config_idx.borrow() + 1) as usize;
                        let prov_config_data = prov_config_data.borrow();
                        for i in 0..prov_config_len {
                            let mut reader = picopb::PbReader::new(&prov_config_data[i]);
                            loop {
                                if reader.is_eof() {
                                    break;
                                }

                                let (key, typ) = reader.next_key().unwrap();
                                if key == 0 {
                                    break;
                                }

                                match typ {
                                    picopb::WireType::Varint => {
                                        reader.next_varint().unwrap();
                                    }
                                    picopb::WireType::Bit32 => {
                                        reader.next_fixed32().unwrap();
                                    }
                                    picopb::WireType::Bit64 => {
                                        reader.next_fixed64().unwrap();
                                    }
                                    picopb::WireType::Bytes => {
                                        let bytes = reader.next_bytes().unwrap();

                                        if key == 12 {
                                            // cmd_set_config
                                            let mut cfg_reader = picopb::PbReader::new(bytes);

                                            let mut ssid = String::new();
                                            let mut password = String::new();

                                            loop {
                                                if cfg_reader.is_eof() {
                                                    break;
                                                }

                                                let (key, typ) = cfg_reader.next_key().unwrap();
                                                if key == 0 {
                                                    break;
                                                }

                                                match typ {
                                                    picopb::WireType::Bytes if key == 1 => {
                                                        let bytes =
                                                            cfg_reader.next_bytes().unwrap();
                                                        ssid.push_str(
                                                            core::str::from_utf8(bytes).unwrap(),
                                                        )
                                                        .unwrap();
                                                    }
                                                    picopb::WireType::Bytes if key == 2 => {
                                                        let bytes =
                                                            cfg_reader.next_bytes().unwrap();
                                                        password
                                                            .push_str(
                                                                core::str::from_utf8(bytes)
                                                                    .unwrap(),
                                                            )
                                                            .unwrap();
                                                    }
                                                    _ => (),
                                                }
                                            }

                                            if !ssid.is_empty() {
                                                return (ssid, password);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                Err(err) => {
                    println!("{:x?}", err);
                }
            }
        }
    }
}

fn provisioned(
    init: &EspWifiInitialization,
    wifi: &'static mut hal::radio::Wifi,
    ssid: &str,
    password: &str,
) {
    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        create_network_interface(&init, wifi, WifiMode::Sta, &mut socket_set_entries);
    let wifi_stack = WifiStack::new(iface, device, sockets, current_millis);

    let client_config = Configuration::Client(ClientConfiguration {
        ssid: ssid.into(),
        password: password.into(),
        ..Default::default()
    });
    let res = controller.set_configuration(&client_config);
    println!("wifi_set_configuration returned {:?}", res);

    controller.start().unwrap();
    println!("is wifi started: {:?}", controller.is_started());

    println!("{:?}", controller.get_capabilities());
    println!("wifi_connect {:?}", controller.connect());

    // wait to get connected
    println!("Wait to get connected");
    loop {
        let res = controller.is_connected();
        match res {
            Ok(connected) => {
                if connected {
                    break;
                }
            }
            Err(err) => {
                println!("{:?}", err);
                loop {}
            }
        }
    }
    println!("{:?}", controller.is_connected());

    // wait for getting an ip address
    println!("Wait to get an ip address");
    loop {
        wifi_stack.work();

        if wifi_stack.is_iface_up() {
            println!("got ip {:?}", wifi_stack.get_ip_info());
            break;
        }
    }

    println!("Start busy loop on main");

    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    loop {
        println!("Making HTTP request");
        socket.work();

        socket
            .open(IpAddress::Ipv4(Ipv4Address::new(142, 250, 185, 115)), 80)
            .unwrap();

        socket
            .write(b"GET / HTTP/1.0\r\nHost: www.mobile-j.de\r\n\r\n")
            .unwrap();
        socket.flush().unwrap();

        let wait_end = current_millis() + 20 * 1000;
        loop {
            let mut buffer = [0u8; 512];
            if let Ok(len) = socket.read(&mut buffer) {
                let to_print = unsafe { core::str::from_utf8_unchecked(&buffer[..len]) };
                print!("{}", to_print);
            } else {
                break;
            }

            if current_millis() > wait_end {
                println!("Timeout");
                break;
            }
        }
        println!();

        socket.disconnect();

        let wait_end = current_millis() + 5 * 1000;
        while current_millis() < wait_end {
            socket.work();
        }
    }
}
