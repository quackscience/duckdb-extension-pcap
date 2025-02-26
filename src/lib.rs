extern crate duckdb;
extern crate duckdb_loadable_macros;
extern crate libduckdb_sys;
extern crate pcap_parser;

use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use duckdb::{
    core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId},
    vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab},
    Connection, Result,
};
use duckdb_loadable_macros::duckdb_entrypoint_c_api;
use libduckdb_sys as ffi;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::{
    error::Error,
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

struct PcapBindData {
    filepath: String,
}

struct PcapReaderWrapper {
    reader: LegacyPcapReader<Box<dyn Read + Send>>,
}

struct PcapInitData {
    reader: Arc<Mutex<Option<PcapReaderWrapper>>>,
    done: AtomicBool,
}

struct PcapVTab;

impl VTab for PcapVTab {
    type InitData = PcapInitData;
    type BindData = PcapBindData;

    fn bind(bind: &BindInfo) -> Result<PcapBindData, Box<dyn Error>> {
        bind.add_result_column(
            "timestamp",
            LogicalTypeHandle::from(LogicalTypeId::Timestamp),
        );
        bind.add_result_column("src_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("dst_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("src_port", LogicalTypeHandle::from(LogicalTypeId::Integer));
        bind.add_result_column("dst_port", LogicalTypeHandle::from(LogicalTypeId::Integer));
        bind.add_result_column(
            "protocol",
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        );
        bind.add_result_column("length", LogicalTypeHandle::from(LogicalTypeId::Integer));
        bind.add_result_column("payload", LogicalTypeHandle::from(LogicalTypeId::Varchar));

        let filepath = bind.get_parameter(0).to_string();
        
        Ok(PcapBindData {
            filepath,
        })
    }

    // Initialize the VTab
    fn init(info: &InitInfo) -> Result<PcapInitData, Box<dyn Error>> {
        let bind_data = info.get_bind_data::<PcapBindData>();
        let filepath = unsafe { (*bind_data).filepath.clone() };

        debug_print!("Opening file: {}", filepath);

        let reader: Box<dyn Read + Send> =
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

        // Create the pcap reader
        let pcap_reader = LegacyPcapReader::new(65536, reader).expect("PcapReader");
        
        let reader_wrapper = PcapReaderWrapper {
            reader: pcap_reader,
        };
        
        Ok(PcapInitData {
            reader: Arc::new(Mutex::new(Some(reader_wrapper))),
            done: AtomicBool::new(false),
        })
    }

    fn func(
        func: &TableFunctionInfo<PcapVTab>,
        output: &mut DataChunkHandle,
    ) -> Result<(), Box<dyn Error>> {
        let init_data = func.get_init_data();

        // Check if we're done
        if init_data.done.load(Ordering::Relaxed) {
            output.set_len(0);
            return Ok(());
        }

        let mut count = 0;
        let mut reached_eof = false;
        let mut packet_data = None;
        
        // First, process a block with careful locking
        {
            let mut reader_guard = match init_data.reader.lock() {
                Ok(guard) => guard,
                Err(_) => return Err("Failed to lock reader".into()),
            };
            
            let reader_wrapper = match reader_guard.as_mut() {
                Some(wrapper) => wrapper,
                None => return Err("Reader is not initialized".into()),
            };
            
            debug_print!("Attempting to read from PCAP file");
            
            // Process in a loop until we find a valid packet or reach EOF
            'packet_loop: loop {
                // Try to get a meaningful block
                let block_result = reader_wrapper.reader.next();
                
                match block_result {
                    Ok((offset, block)) => {
                        debug_print!("Got a block, examining it");
                        match block {
                            // If we have a packet, extract the data from it
                            PcapBlockOwned::Legacy(packet) => {
                                debug_print!("Found a Legacy packet");
                                let ts_micros = packet.ts_sec as i64 * 1_000_000 + packet.ts_usec as i64;
                                let parsed_result = Self::parse_packet(&packet.data);
                                
                                if let Ok((src_ip, dst_ip, src_port, dst_port, l4_protocol, payload)) = parsed_result {
                                    debug_print!("Successfully parsed packet");
                                    // Store all the packet info for processing outside the lock
                                    packet_data = Some((
                                        ts_micros,
                                        src_ip,
                                        dst_ip,
                                        src_port,
                                        dst_port, 
                                        l4_protocol,
                                        packet.origlen,
                                        payload
                                    ));
                                    
                                    // Consume the block and exit the loop - we found a valid packet
                                    reader_wrapper.reader.consume(offset);
                                    break 'packet_loop;
                                } else {
                                    debug_print!("Failed to parse packet");
                                    // Error parsing packet, just consume and continue
                                    reader_wrapper.reader.consume(offset);
                                }
                            },
                            PcapBlockOwned::LegacyHeader(header) => {
                                debug_print!("Found a Legacy header: version={}.{}", 
                                     header.version_major, header.version_minor);
                                reader_wrapper.reader.consume(offset);
                            },
                            // Skip other blocks
                            _ => {
                                debug_print!("Found some other type of block");
                                reader_wrapper.reader.consume(offset);
                            }
                        }
                    },
                    Err(PcapError::Incomplete(needed)) => {
                        debug_print!("Incomplete data, need {} more bytes, trying to refill", needed);
                        // Need to refill
                        if let Err(e) = reader_wrapper.reader.refill() {
                            debug_print!("Failed to refill: {:?}", e);
                            reached_eof = true;
                            break 'packet_loop;
                        } else {
                            debug_print!("Refilled successfully");
                        }
                    },
                    Err(PcapError::Eof) => {
                        debug_print!("Reached EOF");
                        reached_eof = true;
                        break 'packet_loop;
                    },
                    Err(e) => {
                        debug_print!("Error reading PCAP: {:?}", e);
                        reached_eof = true;
                        break 'packet_loop;
                    }
                }
            }
        }
        
        // Handle EOF outside the lock
        if reached_eof {
            init_data.done.store(true, Ordering::Relaxed);
            output.set_len(0);
            return Ok(());
        }
        
        // Process packet data outside the lock
        if let Some((timestamp_micros, src_ip, dst_ip, src_port, dst_port, l4_protocol, packet_len, payload)) = packet_data {
            debug_print!(
                "Processing packet: timestamp={}, src={}:{}, dst={}:{}, proto={}, len={}",
                timestamp_micros,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                l4_protocol,
                packet_len
            );

            // Fill the output vectors with packet data
            output.flat_vector(0).as_mut_slice::<i64>()[count] = timestamp_micros;
            output.flat_vector(1).insert(count, src_ip.as_str());
            output.flat_vector(2).insert(count, dst_ip.as_str());
            output.flat_vector(3).as_mut_slice::<i32>()[count] = src_port as i32;
            output.flat_vector(4).as_mut_slice::<i32>()[count] = dst_port as i32;
            output.flat_vector(5).insert(count, l4_protocol.as_str());
            output.flat_vector(6).as_mut_slice::<i32>()[count] = packet_len as i32;

            // Process the payload for display
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
            output.flat_vector(7).insert(count, payload_str.as_str());

            count += 1;
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

#[duckdb_entrypoint_c_api(ext_name = "pcap_reader", min_duckdb_version = "v1.2.0")]
pub fn extension_entrypoint(con: Connection) -> Result<(), Box<dyn Error>> {
    // Print a simple load message (could be controlled with a verbose flag if needed)
    debug_print!("Loading PCAP reader extension");
    
    con.register_table_function::<PcapVTab>("pcap_reader")
        .expect("Failed to register pcap_reader function");
    
    Ok(())
}
