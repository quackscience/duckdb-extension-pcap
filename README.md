<img src="https://github.com/user-attachments/assets/46a5c546-7e9b-42c7-87f4-bc8defe674e0" width=250 />

# DuckDB PCAP Community Extension 
This experimental rust extension allows reading PCAP files from DuckDB using the [pcap-parser crate](https://crates.io/crates/pcap-parser)

> Experimental: USE AT YOUR OWN RISK!

### 📦 Installation
```sql
INSTALL pcap_reader FROM community;
LOAD pcap_reader;
```

#### Table Functions
- `pcap_reader()`

### Example
```sql
D LOAD '/usr/src/duckdb-extension-pcap/build/debug/pcap_reader.duckdb_extension';
D SELECT * FROM pcap_reader('test/test.pcap') LIMIT 10;
┌────────────┬────────────────┬────────────────┬──────────┬──────────┬──────────┬─────────┬─────────────────────────────────────────────────┐
│ timestamp  │     src_ip     │     dst_ip     │ src_port │ dst_port │ protocol │ length  │                     payload                     │
│  varchar   │    varchar     │    varchar     │ varchar  │ varchar  │ varchar  │ varchar │                     varchar                     │
├────────────┼────────────────┼────────────────┼──────────┼──────────┼──────────┼─────────┼─────────────────────────────────────────────────┤
│ 1733513420 │ xx.xx.xx.xxx   │ yyy.yyy.yy.yyy │ 64078    │ 5080     │ UDP      │ 756     │ UTF8: INVITE sip:810442837619024@yyy.yyy.yy.y…  │
│ 1733513420 │ yyy.yyy.yy.yyy │ xx.xx.xx.xxx   │ 5080     │ 64078    │ UDP      │ 360     │ UTF8: SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP …  │
│ 1733513420 │ yyy.yyy.yy.yyy │ xx.xx.xx.xxx   │ 5080     │ 64078    │ UDP      │ 909     │ UTF8: SIP/2.0 480 Temporarily Unavailable\r\n…  │
├────────────┴────────────────┴────────────────┴──────────┴──────────┴──────────┴─────────┴─────────────────────────────────────────────────┤
│ 3 rows                                                                                                                          8 columns │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

<br>

---

<br>

## Development

### Dependencies
In principle, these extensions can be compiled with the Rust toolchain alone. However, this template relies on some additional
tooling to make life a little easier and to be able to share CI/CD infrastructure with extension templates for other languages:

- Python3
- Python3-venv
- [Make](https://www.gnu.org/software/make)
- Git

Installing these dependencies will vary per platform:
- For Linux, these come generally pre-installed or are available through the distro-specific package manager.
- For MacOS, [homebrew](https://formulae.brew.sh/).
- For Windows, [chocolatey](https://community.chocolatey.org/).

## Building
After installing the dependencies, building is a two-step process. Firstly run:
```shell
make configure
```
This will ensure a Python venv is set up with DuckDB and DuckDB's test runner installed. Additionally, depending on configuration,
DuckDB will be used to determine the correct platform for which you are compiling.

Then, to build the extension run:
```shell
make debug
```
This delegates the build process to cargo, which will produce a shared library in `target/debug/<shared_lib_name>`. After this step, 
a script is run to transform the shared library into a loadable extension by appending a binary footer. The resulting extension is written
to the `build/debug` directory.

To create optimized release binaries, simply run `make release` instead.

## Testing
This extension uses the DuckDB Python client for testing. This should be automatically installed in the `make configure` step.
The tests themselves are written in the SQLLogicTest format, just like most of DuckDB's tests. A sample test can be found in
`test/sql/<extension_name>.test`. To run the tests using the *debug* build:

```shell
make test_debug
```

or for the *release* build:
```shell
make test_release
```

### Version switching 
Testing with different DuckDB versions is really simple:

First, run 
```
make clean_all
```
to ensure the previous `make configure` step is deleted.

Then, run 
```
DUCKDB_TEST_VERSION=v1.1.2 make configure
```
to select a different duckdb version to test with

Finally, build and test with 
```
make debug
make test_debug
```

### Known issues
This is a bit of a footgun, but the extensions produced by this template may (or may not) be broken on windows on python3.11 
with the following error on extension load:
```shell
IO Error: Extension '<name>.duckdb_extension' could not be loaded: The specified module could not be found
```
This was resolved by using python 3.12
