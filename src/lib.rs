extern crate duckdb;
extern crate duckdb_loadable_macros;
extern crate libduckdb_sys;
extern crate pcap_parser;

use std::mem::ManuallyDrop;

use duckdb::{
    core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId},
    vtab::{BindInfo, Free, FunctionInfo, InitInfo, VTab},
    Connection, Result,
};
use duckdb_loadable_macros::duckdb_entrypoint_c_api;
use libduckdb_sys as ffi;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::{
    error::Error,
    ffi::{c_char, CStr, CString},
    fs::File,
    io::{Cursor, Read},
};

macro_rules! debug_print {
    ($($arg:tt)*) => {
        if std::env::var("DEBUG").is_ok() {
            eprintln!("[PCAP Debug] {}", format!($($arg)*));
        }
    };
}

#[repr(C)]
struct PcapBindData {
    filepath: *mut c_char,
}

#[repr(C)]
struct PcapInitData {
    reader: Option<ManuallyDrop<LegacyPcapReader<Box<dyn Read>>>>,
    done: bool,
}

impl Free for PcapBindData {
    fn free(&mut self) {
        unsafe {
            if !self.filepath.is_null() {
                drop(CString::from_raw(self.filepath));
            }
        }
    }
}

struct PcapVTab;

impl Free for PcapInitData {
    fn free(&mut self) {
        self.reader = None;
    }
}

impl VTab for PcapVTab {
    type InitData = PcapInitData;
    type BindData = PcapBindData;

    unsafe fn bind(bind: &BindInfo, data: *mut PcapBindData) -> Result<(), Box<dyn Error>> {
        bind.add_result_column(
            "timestamp",
            LogicalTypeHandle::from(LogicalTypeId::Timestamp),
        );
        bind.add_result_column("src_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("dst_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("src_port", LogicalTypeHandle::from(LogicalTypeId::Integer));
        bind.add_result_column("dst_port", LogicalTypeHandle::from(LogicalTypeId::Integer));
        bind.add_result_column(
            "L4 protocol",
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        );
        bind.add_result_column("length", LogicalTypeHandle::from(LogicalTypeId::Integer));
        bind.add_result_column("payload", LogicalTypeHandle::from(LogicalTypeId::Varchar));

        let filepath = bind.get_parameter(0).to_string();
        unsafe {
            (*data).filepath = CString::new(filepath)?.into_raw();
        }
        Ok(())
    }

    // Initialize the VTab
    unsafe fn init(info: &InitInfo, data: *mut PcapInitData) -> Result<(), Box<dyn Error>> {
        let bind_data = info.get_bind_data::<PcapBindData>();
        let filepath = unsafe { CStr::from_ptr((*bind_data).filepath).to_str()? };

        debug_print!("Opening file: {}", filepath);

        let reader: Box<dyn Read> =
            if filepath.starts_with("http://") || filepath.starts_with("https://") {
                debug_print!("Using HTTP reader for {}", filepath);

                // Create a channel to receive the response
                let (tx, rx) = std::sync::mpsc::channel();

                let request = ehttp::Request::get(filepath);
                ehttp::fetch(request, move |result: ehttp::Result<ehttp::Response>| {
                    tx.send(result).unwrap();
                });

                // Wait for the response
                let response = rx
                    .recv()?
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Box::new(Cursor::new(response.bytes))
            } else {
                debug_print!("Using file reader for {}", filepath);
                Box::new(File::open(filepath)?)
            };

        unsafe {
            (*data).reader = Some(ManuallyDrop::new(
                LegacyPcapReader::new(65536, reader).expect("PcapReader"),
            ));
            (*data).done = false;
        }
        Ok(())
    }

    unsafe fn func(
        func: &FunctionInfo,
        output: &mut DataChunkHandle,
    ) -> Result<(), Box<dyn Error>> {
        let init_data = func.get_init_data::<PcapInitData>();

        unsafe {
            if (*init_data).done {
                output.set_len(0);
                return Ok(());
            }
        }

        let mut count = 0;

        // Read packets from the pcap file
        'read_loop: loop {
            let next_result = unsafe { (*init_data).reader.as_mut().unwrap().next() };

            // Handle the next packet
            let (offset, block) = match next_result {
                Ok(result) => result,
                Err(PcapError::Incomplete(_)) => {
                    unsafe {
                        (*init_data).reader.as_mut().unwrap().refill()?;
                    }
                    continue 'read_loop;
                }
                Err(PcapError::Eof) => {
                    unsafe {
                        (*init_data).done = true;
                    }
                    output.set_len(count);
                    return Ok(());
                }
                Err(e) => return Err(Box::new(e)),
            };

            // Process the block
            match block {
              
                // Handle the packet
                PcapBlockOwned::Legacy(packet) => {
                    let parsed = Self::parse_packet(&packet.data)?;
                    let (src_ip, dst_ip, src_port, dst_port, l4_protocol, payload) = parsed;
                    let timestamp_micros = packet.ts_sec as i64 * 1_000_000 + packet.ts_usec as i64;

                    debug_print!(
                        "Processing packet: timestamp={}, src={}:{}, dst={}:{}, proto={}, len={}",
                        timestamp_micros,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        l4_protocol,
                        packet.origlen
                    );

                    output.flat_vector(0).as_mut_slice::<i64>()[0] = timestamp_micros;
                    output.flat_vector(1).insert(count, CString::new(src_ip)?);
                    output.flat_vector(2).insert(count, CString::new(dst_ip)?);
                    output.flat_vector(3).as_mut_slice::<i32>()[0] = src_port as i32;
                    output.flat_vector(4).as_mut_slice::<i32>()[0] = dst_port as i32;
                    output.flat_vector(5).insert(count, CString::new(l4_protocol)?);
                    output.flat_vector(6).as_mut_slice::<i32>()[0] = packet.origlen as i32;

                    let payload_str = if !payload.is_empty() {
                        if let Ok(utf8_str) = std::str::from_utf8(&payload) {
                            if utf8_str
                                .chars()
                                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                            {
                                format!("{}", utf8_str)
                            } else {
                                let hex_str: Vec<String> = payload
                                    .iter()
                                    .take(32)
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                format!(
                                    "{}{}",
                                    hex_str.join(" "),
                                    if payload.len() > 32 { " ..." } else { "" }
                                )
                            }
                        } else {
                            let hex_str: Vec<String> = payload
                                .iter()
                                .take(32)
                                .map(|b| format!("{:02x}", b))
                                .collect();
                            format!(
                                "{}{}",
                                hex_str.join(" "),
                                if payload.len() > 32 { " ..." } else { "" }
                            )
                        }
                    } else {
                        "empty".to_string()
                    };
                    output
                        .flat_vector(7)
                        .insert(count, CString::new(payload_str)?);

                    count += 1;

                    unsafe {
                        (*init_data).reader.as_mut().unwrap().consume(offset);
                    }
                    break 'read_loop;
                }

                // Skip non-packet blocks
                PcapBlockOwned::LegacyHeader(_) | _ => {
                    unsafe {
                        (*init_data).reader.as_mut().unwrap().consume(offset);
                    }
                    continue 'read_loop;
                }
            }
        }
        // Set the number of rows in the output
        output.set_len(count);
        Ok(())
    }

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        Some(vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)])
    }
}

impl PcapVTab {
    /*
    function parse_packet
    Return the source IP, destination IP, source port, destination port, L4 protocol, payload
    */
    fn parse_packet(
        data: &[u8],
    ) -> Result<(String, String, u16, u16, String, Vec<u8>), Box<dyn Error>> {
        let mut src_ip = String::from("0.0.0.0");
        let mut dst_ip = String::from("0.0.0.0");
        let mut src_port = 0;
        let mut dst_port = 0;
        let mut l4_protocol = String::from("UNKNOWN");
        let mut payload = Vec::new();

        debug_print!("Parsing packet of length: {}", data.len());

        // Parse the Ethernet header
        if data.len() >= 14 {
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            debug_print!("Ethertype: 0x{:04x}", ethertype);

            let mut transport_header_start = 0;
            let mut ip_protocol = 0;

            // Parse the IP header
            if ethertype == 0x0800 && data.len() >= 34 {
                let ip_header_len = (data[14] & 0x0f) * 4;
                debug_print!("IP header length: {}", ip_header_len);

                src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);

                ip_protocol = data[23];
                debug_print!("IP Protocol: {}", ip_protocol);

                transport_header_start = 14 + ip_header_len as usize;
            }
            // Parse the IPv6 header
            else if ethertype == 0x86DD && data.len() >= 54 {
                let ip_header_len = 54;
                debug_print!("IPv6 header length: {}", ip_header_len);

                src_ip = format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    u16::from_be_bytes([data[22], data[23]]),
                    u16::from_be_bytes([data[24], data[25]]),
                    u16::from_be_bytes([data[26], data[27]]),
                    u16::from_be_bytes([data[28], data[29]]),
                    u16::from_be_bytes([data[30], data[31]]),
                    u16::from_be_bytes([data[32], data[33]]),
                    u16::from_be_bytes([data[34], data[35]]),
                    u16::from_be_bytes([data[36], data[37]])
                );
                dst_ip = format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    u16::from_be_bytes([data[38], data[39]]),
                    u16::from_be_bytes([data[40], data[41]]),
                    u16::from_be_bytes([data[42], data[43]]),
                    u16::from_be_bytes([data[44], data[45]]),
                    u16::from_be_bytes([data[46], data[47]]),
                    u16::from_be_bytes([data[48], data[49]]),
                    u16::from_be_bytes([data[50], data[51]]),
                    u16::from_be_bytes([data[52], data[53]])
                );

                ip_protocol = data[20];
                debug_print!("IP protocol: {}", ip_protocol);

                transport_header_start = ip_header_len as usize;
            }

            // Parse the transport header
            match ip_protocol {
                6 => {
                    l4_protocol = String::from("TCP");
                    if data.len() >= transport_header_start + 4 {
                        src_port = u16::from_be_bytes([
                            data[transport_header_start],
                            data[transport_header_start + 1],
                        ]);
                        debug_print!("TCP Source Port: {}", src_port);
                        dst_port = u16::from_be_bytes([
                            data[transport_header_start + 2],
                            data[transport_header_start + 3],
                        ]);
                        debug_print!("TCP Destination Port: {}", dst_port);
                    }
                }
                17 => {
                    l4_protocol = String::from("UDP");
                    if data.len() >= transport_header_start + 4 {
                        src_port = u16::from_be_bytes([
                            data[transport_header_start],
                            data[transport_header_start + 1],
                        ]);
                        debug_print!("UDP Source Port: {}", src_port);
                        dst_port = u16::from_be_bytes([
                            data[transport_header_start + 2],
                            data[transport_header_start + 3],
                        ]);
                        debug_print!("UDP Destination Port: {}", dst_port);
                    }
                }
                _ => l4_protocol = format!("IP({})", ip_protocol),
            }

            // Parse the payload
            let payload_start = transport_header_start
                + match ip_protocol {
                    6 => 20,
                    17 => 8,
                    _ => 0,
                };

            // Copy the payload
            if data.len() > payload_start {
                payload = data[payload_start..].to_vec();
            }
        }

        // Print the parsed packet
        debug_print!(
            "Parsed packet: {}:{} -> {}:{} ({})",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            l4_protocol
        );

        // Return the parsed packet
        Ok((src_ip, dst_ip, src_port, dst_port, l4_protocol, payload))
    }
}

#[duckdb_entrypoint_c_api(ext_name = "pcap_reader", min_duckdb_version = "v0.0.1")]
pub unsafe fn extension_entrypoint(con: Connection) -> Result<(), Box<dyn Error>> {
    con.register_table_function::<PcapVTab>("pcap_reader")
        .expect("Failed to register pcap_reader function");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a simple IPv4 packet
    fn create_ipv4_tcp_packet() -> Vec<u8> {
        let packet = vec![
            // Ethernet header (14 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // IPv4 EtherType
            // IPv4 header (20 bytes)
            0x45, 0x00, // Version & IHL, DSCP & ECN
            0x00, 0x28, // Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, // TTL, Protocol (6 = TCP)
            0x00, 0x00, // Header Checksum
            192, 168, 1, 100, // Source IP (192.168.1.100)
            10, 0, 0, 1, // Destination IP (10.0.0.1)
            // TCP header (20 bytes)
            0x12, 0x34, // Source Port (4660)
            0x45, 0x67, // Destination Port (17767)
            0x00, 0x00, 0x00, 0x00, // Sequence Number
            0x00, 0x00, 0x00, 0x00, // Acknowledgment Number
            0x50, 0x00, // Data Offset & Flags
            0x00, 0x00, // Window Size
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent Pointer
            // Payload
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello" in ASCII
        ];
        packet
    }

    // Helper function to create a simple IPv6 packet
    fn create_ipv6_udp_packet() -> Vec<u8> {
        let packet = vec![
            // Ethernet header (14 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x86, 0xDD, // IPv6 EtherType
            // IPv6 header (40 bytes)
            0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
            0x00, 0x08, // Payload Length
            17, 0x40, // Next Header (17 = UDP), Hop Limit
            0x20, 0x01, 0x0d, 0xb8, // Source IP (2001:db8::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01,
            0x0d, 0xb8, // Destination IP (2001:db8::2)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            // UDP header (8 bytes)
            0x89, 0x13, // Source Port (35091)
            0x12, 0x34, // Destination Port (4660)
            0x00, 0x08, // Length
            0x00, 0x00, // Checksum
            // Payload
            0x54, 0x65, 0x73, 0x74, // "Test" in ASCII
        ];
        packet
    }

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        let packet = create_ipv4_tcp_packet();
        let result = PcapVTab::parse_packet(&packet).unwrap();

        assert_eq!(result.0, "192.168.1.100"); // Source IP
        assert_eq!(result.1, "10.0.0.1"); // Destination IP
        assert_eq!(result.2, 4660); // Source Port
        assert_eq!(result.3, 17767); // Destination Port
        assert_eq!(result.4, "TCP"); // Protocol
        assert_eq!(result.5, b"Hello"); // Payload
    }

    #[test]
    fn test_parse_ipv6_udp_packet() {
        let packet = create_ipv6_udp_packet();
        let result = PcapVTab::parse_packet(&packet).unwrap();

        assert_eq!(result.0, "2001:db8:0:0:0:0:0:1"); // Source IP
        assert_eq!(result.1, "2001:db8:0:0:0:0:0:2"); // Destination IP
        assert_eq!(result.2, 35091); // Source Port
        assert_eq!(result.3, 4660); // Destination Port
        assert_eq!(result.4, "UDP"); // Protocol
        assert_eq!(result.5, b"Test"); // Payload
    }

    #[test]
    fn test_parse_small_packet() {
        let packet = vec![0; 10]; // Packet too small to contain headers
        let result = PcapVTab::parse_packet(&packet).unwrap();

        assert_eq!(result.0, "0.0.0.0"); // Default IP
        assert_eq!(result.1, "0.0.0.0"); // Default IP
        assert_eq!(result.2, 0); // Default Port
        assert_eq!(result.3, 0); // Default Port
        assert_eq!(result.4, "UNKNOWN"); // Default Protocol
        assert!(result.5.is_empty()); // Empty Payload
    }

    #[test]
    fn test_parse_unknown_protocol() {
        let mut packet = create_ipv4_tcp_packet();
        packet[23] = 100; // Change protocol number to unknown value
        let result = PcapVTab::parse_packet(&packet).unwrap();

        assert_eq!(result.4, "IP(100)"); // Unknown protocol
    }
}
