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
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::{
    error::Error,
    ffi::{c_char, CStr, CString},
    fs::File,
};

macro_rules! debug_print {
    ($($arg:tt)*) => {
    //    eprintln!("[PCAP Debug] {}", format!($($arg)*));
    };
}

#[repr(C)]
struct PcapBindData {
    filepath: *mut c_char,
}

#[repr(C)]
struct PcapInitData {
    reader: Option<ManuallyDrop<LegacyPcapReader<File>>>,
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
        // Explicitly don't drop the reader to keep file handle alive
        self.reader = None;
    }
}

impl VTab for PcapVTab {
    type InitData = PcapInitData;
    type BindData = PcapBindData;

    unsafe fn bind(bind: &BindInfo, data: *mut PcapBindData) -> Result<(), Box<dyn Error>> {
        bind.add_result_column("timestamp", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("src_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("dst_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("src_port", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("dst_port", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("protocol", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("length", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("payload", LogicalTypeHandle::from(LogicalTypeId::Varchar));  // Changed from Blob to Varchar

        let filepath = bind.get_parameter(0).to_string();
        unsafe {
            (*data).filepath = CString::new(filepath)?.into_raw();
        }
        Ok(())
    }

    unsafe fn init(info: &InitInfo, data: *mut PcapInitData) -> Result<(), Box<dyn Error>> {
        let bind_data = info.get_bind_data::<PcapBindData>();
        let filepath = unsafe { CStr::from_ptr((*bind_data).filepath).to_str()? };
        let file = File::open(filepath)?;
        debug_print!("Initializing reader for file: {}", filepath);
    
        unsafe {
            (*data).reader = Some(ManuallyDrop::new(
                LegacyPcapReader::new(65536, file).expect("PcapReader")
            ));
            (*data).done = false;
        }
        Ok(())
    }

    // func start
    unsafe fn func(func: &FunctionInfo, output: &mut DataChunkHandle) -> Result<(), Box<dyn Error>> {
    let init_data = func.get_init_data::<PcapInitData>();
    
    unsafe {
        if (*init_data).done {
            output.set_len(0);
            return Ok(());
        }
    }
    
    let reader = unsafe { (*init_data).reader.as_mut() }.unwrap();
    let mut count = 0;
    let mut next_result = reader.next();
    
    while let Err(PcapError::Incomplete(_)) = next_result {
        unsafe { (*init_data).reader.as_mut() }.unwrap().refill()?;
        next_result = unsafe { (*init_data).reader.as_mut() }.unwrap().next();
    }
    
    match next_result {
        Ok((offset, block)) => {
            let (ts_sec_str, length_str, src_ip, dst_ip, src_port, dst_port, protocol, payload) = match block {
                PcapBlockOwned::Legacy(packet) => {
                    let parsed = Self::parse_packet(&packet.data)?;
                    let (src_ip, dst_ip, src_port, dst_port, protocol, payload) = parsed;
                    
                    let payload_str = if !payload.is_empty() {
                        if let Ok(utf8_str) = std::str::from_utf8(&payload) {
                            if utf8_str.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                                format!("{}", utf8_str)
                            } else {
                                let hex_str: Vec<String> = payload.iter()
                                    .take(32)
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                format!("{}{}", hex_str.join(" "), 
                                    if payload.len() > 32 { " ..." } else { "" })
                            }
                        } else {
                            let hex_str: Vec<String> = payload.iter()
                                .take(32)
                                .map(|b| format!("{:02x}", b))
                                .collect();
                            format!("{}{}", hex_str.join(" "), 
                                if payload.len() > 32 { " ..." } else { "" })
                        }
                    } else {
                        "empty".to_string()
                    };
                    
                    (packet.ts_sec.to_string(), packet.origlen.to_string(), 
                     src_ip, dst_ip, src_port.to_string(), dst_port.to_string(), 
                     protocol, payload_str)
                },
                PcapBlockOwned::LegacyHeader(_) => {
                    ("0".to_string(), "0".to_string(), "0.0.0.0".to_string(), "0.0.0.0".to_string(),
                     "0".to_string(), "0".to_string(), "UNKNOWN".to_string(), "empty".to_string())
                },
                _ => {
                    ("0".to_string(), "0".to_string(), "0.0.0.0".to_string(), "0.0.0.0".to_string(),
                     "0".to_string(), "0".to_string(), "UNKNOWN".to_string(), "empty".to_string())
                }
            };
            
            output.flat_vector(0).insert(count, CString::new(ts_sec_str)?);
            output.flat_vector(1).insert(count, CString::new(src_ip)?);
            output.flat_vector(2).insert(count, CString::new(dst_ip)?);
            output.flat_vector(3).insert(count, CString::new(src_port)?);
            output.flat_vector(4).insert(count, CString::new(dst_port)?);
            output.flat_vector(5).insert(count, CString::new(protocol)?);
            output.flat_vector(6).insert(count, CString::new(length_str)?);
            output.flat_vector(7).insert(count, CString::new(payload)?);
            
            count += 1;
            unsafe { (*init_data).reader.as_mut() }.unwrap().consume(offset);
        },
        Err(PcapError::Eof) => {
            unsafe { (*init_data).done = true; }
            output.set_len(count);
            return Ok(());
        },
        Err(e) => return Err(Box::new(e)),
    }
    
    output.set_len(count);
    Ok(())
    }
    // func stop

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        Some(vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)])
    }
}

impl PcapVTab {
    fn parse_packet(data: &[u8]) -> Result<(String, String, u16, u16, String, Vec<u8>), Box<dyn Error>> {
        let mut src_ip = String::from("0.0.0.0");
        let mut dst_ip = String::from("0.0.0.0");
        let mut src_port = 0;
        let mut dst_port = 0;
        let mut protocol = String::from("UNKNOWN");
        let mut payload = Vec::new();

        debug_print!("Parsing packet of length: {}", data.len());

        if data.len() >= 14 { // Minimum Ethernet frame size
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            debug_print!("Ethertype: 0x{:04x}", ethertype);
            
            if ethertype == 0x0800 && data.len() >= 34 { // IPv4
                let ip_header_len = (data[14] & 0x0f) * 4;
                debug_print!("IP header length: {}", ip_header_len);
                
                // Extract IP addresses
                src_ip = format!("{}.{}.{}.{}", 
                    data[26], data[27], data[28], data[29]);
                dst_ip = format!("{}.{}.{}.{}", 
                    data[30], data[31], data[32], data[33]);
                
                // Get IP protocol
                let ip_protocol = data[23];
                debug_print!("IP Protocol: {}", ip_protocol);
                
                let transport_header_start = 14 + ip_header_len as usize;
                
                match ip_protocol {
                    6 => {  // TCP
                        protocol = String::from("TCP");
                        if data.len() >= transport_header_start + 4 {
                            src_port = u16::from_be_bytes([data[transport_header_start], data[transport_header_start + 1]]);
                            dst_port = u16::from_be_bytes([data[transport_header_start + 2], data[transport_header_start + 3]]);
                        }
                    },
                    17 => { // UDP
                        protocol = String::from("UDP");
                        if data.len() >= transport_header_start + 4 {
                            src_port = u16::from_be_bytes([data[transport_header_start], data[transport_header_start + 1]]);
                            dst_port = u16::from_be_bytes([data[transport_header_start + 2], data[transport_header_start + 3]]);
                        }
                    },
                    _ => protocol = format!("IP({})", ip_protocol),
                }
                
                // Extract payload
                let payload_start = transport_header_start + match ip_protocol {
                    6 => 20,  // TCP header size (without options)
                    17 => 8,  // UDP header size
                    _ => 0,
                };
                
                if data.len() > payload_start {
                    payload = data[payload_start..].to_vec();
                }
                
            } else if ethertype == 0x86DD { // IPv6
                protocol = String::from("IPv6");
                // TODO: Add IPv6 parsing
            }
        }

        debug_print!("Parsed packet: {}:{} -> {}:{} ({})", 
            src_ip, src_port, dst_ip, dst_port, protocol);
        
        Ok((src_ip, dst_ip, src_port, dst_port, protocol, payload))
    }
}

const EXTENSION_NAME: &str = env!("CARGO_PKG_NAME");

#[duckdb_entrypoint_c_api(ext_name = "pcap_reader", min_duckdb_version = "v0.0.1")]
pub unsafe fn extension_entrypoint(con: Connection) -> Result<(), Box<dyn Error>> {
    con.register_table_function::<PcapVTab>("pcap_reader")
        .expect("Failed to register pcap_reader function");
    Ok(())
}
