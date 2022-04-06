# Wirdigen

![example workflow](https://github.com/cerclique/wirdigen/actions/workflows/rust-build.yml/badge.svg)
![example workflow](https://github.com/cerclique/wirdigen/actions/workflows/rust-test.yml/badge.svg)
![example workflow](https://github.com/cerclique/wirdigen/actions/workflows/rust-coverage.yml/badge.svg)
![example workflow](https://github.com/cerclique/wirdigen/actions/workflows/rust-audit.yml/badge.svg)
![example workflow](https://github.com/cerclique/wirdigen/actions/workflows/rust-clippy.yml/badge.svg)

---

## Overview

Wirdigen (_Wireshark Dissector Generator_) is a library that aims to generate LUA plugin for Wireshark based on a JSON description of the packet you want to dissect.

For more information about packet dissection, please refer to Wireshark [documentation](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html) and [wiki](https://wiki.wireshark.org/Lua/Dissectors).

## How to use

The library is composed of two tools:

### Validator

Validator compare a JSON packet description with a predefined JSON schema to ensure data integrity for plugin generation.

If the packet description is invalid, errors are automatically reported to the user through `stderr` with detailled location/description.

``` rust
use wirdigen::validator::Validator;
use wirdigen::error::WirdigenError;

fn foo() -> Result<(), WirdigenError> {
    // Load JSON file
    let file_path = "./data/example_dissector.json";
    let file = File::open(file_path)?;
    let rdr = BufReader::new(file);

    // Create serde JSON value from the file
    let value: Value = serde_json::from_reader(rdr)?;

    // Create Validator object
    let val = Validator::new()?;

    // Call to validation function
    match val.validate(&value) {
        true => println!("{}: VALID", file_path),
        false => println!("{}: INVALID", file_path)
    }
    Ok(())
}
```

### Generator

Generator generate LUA plugin based on JSON input given by the user.

```rust
use wirdigen::generator::Generator;
use wirdigen::error::WirdigenError;

fn foo() -> Result<(), WirdigenError> {
    // Load JSON file
    let file_path = "./data/example_dissector.json";
    let file = File::open(file_path)?;
    let rdr = BufReader::new(file);

    // Create Generator object
    let gen = Generator::default();
    // let gen = Generator::new();   <-- Alternative

    // Generate from a reader source
    let generated_file_path: String = gen.from_reader(rdr)?;
    println!("Generated: {}", generated_file_path);
    Ok(())
}
```

**Note:**

The `Generator` does not perform any pre-validation on the user input. This is the role of the `Validator`. In case of invalid file, method from `Generator` will return appropriate `Err(WirdigenError)`.

To avoid these kinds of problem, it's best to first perform a validation and, then, generate the associate LUA plugin.

`Generator` object also have a `from_value` method to reuse the serde-json `Value` from the validation task for the generation.

```rust
fn foo() -> Result<(), WirdigenError> {
    // Open the JSON file
    let file_path = "./data/example_dissector.json";
    let file = File::open(file_path)?;
    let rdr = BufReader::new(file);

    // Create serde JSON value from the file
    let value: Value = serde_json::from_reader(rdr)?;

    // Create Validator object
    let val = Validator::new()?;

    // Call to validation method
    if val.validate(&value) {
        // Create Generator object
        let gen = Generator::default();

        // Generate plugin from validated data
        let generated_file_path: String = gen.from_value(value)?;
        println!("{}", generated_file_path);
    }
    else {
        println!("Invalid user input: {}", file_path);
    }
    Ok(())
}
```

By default, the plugin is generated in the temporary folder of the machine:
- Unix: `/tmp`
- Windows: `C:\Temp`


The user can modify the output directory though `set_output_directory()` method and retrieve the current one through `get_output_directory()` method.

```rust
fn foo {
    let mut gen = Generator::default();

    println!("{}", gen.get_output_directory());

    let new_output = "/Documents/MyDissectors";
    gen.set_output_directory(new_output);

    println!("{}", gen.get_output_directory());
}
```

**Note:**

The method `set_output_directory` does not create non-existent directory from user input.
If the output directory is not reachable, the error will be propagated from the generation method when trying to create the final LUA file.

## Dissector format

A JSON dissector description is composed of 3 elements:
- `name`
- `connection`
- `data`

### **Name**

`name` element is a string (max size: 20) representing the name of the protocol to dissect that  will be used inside Wireshark to identify your packet.

Note: This name is also used for the generated LUA file. For example, if the attribute is `MY_PROTO`, the generated plugin will be called `dissector_MY_PROTO.lua`.

### **Connection**

The `connection` object contains 2 fields :
- `protocol`: String. Either `udp` or `tcp`.
- `ports`: Array of port the dissector need to spy (between 1 and 65365).

### **Data**

`data` is an array of object describing the packet. Each object define a chunk of the packet we want to identify.

Each chunk must contains the following attributes:
- `name`: String (max size: 20).
- `format`: String representing the type of the chunk. Available values are `none`, `uint8`, `uint16`, `uint24`, `uint32`, `uint64`, `int8`, `int16`, `int24`, `int32`, `int64`, `framenum`, `bool`, `absolute_time`, `relative_time`, `float`, `double`, `string`, `stringz`, `bytes`, `ubytes`, `ipv4`, `ipv6`, `ether`, `guid`, `oid`, `protocol`, `rel_oid`, `systemid`, `eui64`.
- `filter_name`: String (max size: 20) representing the chunk.
- `description`: String (max size: 50). Short description of the chunk.
- `base`: String representing how the chunk should be displayed. Available values are `NONE`, `DEC`, `HEX`, `OCT`, `DEC_HEX`, `HEX_DEC`, `UNIT_STRING`, `RANGE_STRING`.
- `offset`: Position offset, in byte, from the begining of the packet.
- `size`: Size, in byte, of the chunk inside the packet.

## Import dissector into Wireshark

=== TODO ===