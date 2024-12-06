extern crate duckdb;
extern crate duckdb_loadable_macros;
extern crate libduckdb_sys;
extern crate pcap_parser;

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

#[repr(C)]
struct PcapBindData {
    filepath: *mut c_char,
}

#[repr(C)]
struct PcapInitData {
//    reader: Option<PcapNGReader<File>>,
    reader: Option<LegacyPcapReader<File>>,
}

struct PcapVTab;

impl Free for PcapBindData {
    fn free(&mut self) {
        unsafe {
            if !self.filepath.is_null() {
                drop(CString::from_raw(self.filepath));
            }
        }
    }
}

impl Free for PcapInitData {}

impl VTab for PcapVTab {
    type InitData = PcapInitData;
    type BindData = PcapBindData;

    unsafe fn bind(bind: &BindInfo, data: *mut PcapBindData) -> Result<(), Box<dyn Error>> {
        bind.add_result_column("timestamp", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("src_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("dst_ip", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("length", LogicalTypeHandle::from(LogicalTypeId::Varchar));

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
        
        unsafe {
            (*data).reader = Some(LegacyPcapReader::new(65536, file).expect("PcapReader"));
        }
        Ok(())
    }

    unsafe fn func(func: &FunctionInfo, output: &mut DataChunkHandle) -> Result<(), Box<dyn Error>> {
        let init_data = func.get_init_data::<PcapInitData>();
        let reader = unsafe { (*init_data).reader.as_mut() }.unwrap();
        let mut count = 0;

        let mut next_result = reader.next();
        while let Err(PcapError::Incomplete(_)) = next_result {
            unsafe { (*init_data).reader.as_mut() }.unwrap().refill()?;
            next_result = unsafe { (*init_data).reader.as_mut() }.unwrap().next();
        }

        match next_result {
            Ok((offset, block)) => {
                let (ts_sec_str, length_str) = match block {
                    PcapBlockOwned::Legacy(packet) => {
                        (packet.ts_sec.to_string(), packet.origlen.to_string())
                    },
                    PcapBlockOwned::LegacyHeader(_) => {
                        ("0".to_string(), "0".to_string())
                    },
                    _ => ("0".to_string(), "0".to_string()),
                };

                output.flat_vector(0).insert(count, CString::new(ts_sec_str)?);
                output.flat_vector(1).insert(count, CString::new("0.0.0.0")?);
                output.flat_vector(2).insert(count, CString::new("0.0.0.0")?);
                output.flat_vector(3).insert(count, CString::new(length_str)?);
                
                count += 1;
                unsafe { (*init_data).reader.as_mut() }.unwrap().consume(offset);
            },
            Err(PcapError::Eof) => {
                output.set_len(0);
                return Ok(());
            },
            Err(e) => return Err(Box::new(e)),
        }
        
        output.set_len(count);
        Ok(())
    }

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        Some(vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)])
    }
}

const EXTENSION_NAME: &str = env!("CARGO_PKG_NAME");

#[duckdb_entrypoint_c_api(ext_name = "pcap_reader", min_duckdb_version = "v0.0.1")]
pub unsafe fn extension_entrypoint(con: Connection) -> Result<(), Box<dyn Error>> {
    con.register_table_function::<PcapVTab>("pcap_reader")
        .expect("Failed to register pcap_reader function");
    Ok(())
}
