<img src="https://github.com/user-attachments/assets/46a5c546-7e9b-42c7-87f4-bc8defe674e0" width=250 />

# DuckDB PCAP Community Extension 
This experimental rust extension allows reading PCAP files from DuckDB using the [pcap-parser crate](https://crates.io/crates/pcap-parser)

> Experimental: USE AT YOUR OWN RISK!

### 📦 Installation
```sql
INSTALL pcap_reader FROM community;
LOAD pcap_reader;
```

### Example
```sql
D SELECT * FROM pcap_reader('test/test.pcap') LIMIT 3;
┌─────────────────────┬────────────────┬────────────────┬──────────┬──────────┬──────────┬────────┬───────────────────────────────────────────┐
│      timestamp      │     src_ip     │     dst_ip     │ src_port │ dst_port │ protocol │ length │                 payload                   │
│      timestamp      │    varchar     │    varchar     │ int32    │ int32    │ varchar  │ int32  │                 varchar                   │
├─────────────────────┼────────────────┼────────────────┼──────────┼──────────┼──────────┼────────┼───────────────────────────────────────────┤
│ 2024-12-06 19:30:2… │ xx.xx.xx.xxx   │ yyy.yyy.yy.yyy │ 64078    │ 5080     │ UDP      │ 756    │ INVITE sip:810442837619024@yyy.yyy.yy.y…  │
│ 2024-12-06 19:30:2… │ yyy.yyy.yy.yyy │ xx.xx.xx.xxx   │ 5080     │ 64078    │ UDP      │ 360    │ SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP …  │
│ 2024-12-06 19:30:2… │ yyy.yyy.yy.yyy │ xx.xx.xx.xxx   │ 5080     │ 64078    │ UDP      │ 909    │ SIP/2.0 480 Temporarily Unavailable\r\n…  │
├─────────────────────┴────────────────┴────────────────┴──────────┴──────────┴──────────┴────────┴───────────────────────────────────────────┤
│ 3 rows                                                                                                                            8 columns │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
