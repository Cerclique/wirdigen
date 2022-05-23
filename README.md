![RustCI](https://github.com/cerclique/wirdigen/actions/workflows/rust-ci.yml/badge.svg)
[![Codecov](https://codecov.io/gh/Cerclique/wirdigen/branch/master/graph/badge.svg?token=7TATDXMKQA)](https://codecov.io/gh/Cerclique/wirdigen)
![RustAudit](https://github.com/cerclique/wirdigen/actions/workflows/rust-audit.yml/badge.svg)

---


### Table of Contents

* [Overview](#overview)
* [How to use](#howtouse)
    * [Validator](#howtouse_validator)
    * [Generator](#howtouse_generator)
* [Dissector format](#dissector_format)
    * [Name](#dissector_name)
    * [Endianess](#dissector_endianness)
    * [Connection](#dissector_connection)
    * [Data](#dissector_data)
* [Compatibility matrices](#compat_matrices)
    * [Numeric](#matrix_numeric)
    * [Time](#matrix_time)
    * [Raw](#matrix_raw)
    * [Specific](#matrix_specific)
* [Import dissector into wireshark](#import_dissector)
* [Roadmap](#roadmap)
* [Related tools](#related_tools)

# **Overview** <a class="anchor" id="overview"></a>

**Wirdigen** (_**Wir**eshark **Di**ssector **Gen**erator_) is a small library that aims to generate LUA dissector for Wireshark based on a JSON description of the packet you want to analyze.

For more information about packet dissection, please refer to Wireshark [documentation](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html) and [wiki](https://wiki.wireshark.org/Lua/Dissectors).

# **How to use** <a class="anchor" id="howtouse"></a>

The library is composed of two tools:

## **Validator** <a class="anchor" id="howtouse_validator"></a>

`Validator` compare a JSON packet description with a predefined JSON schema to ensure data integrity for plugin generation.

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

## **Generator** <a class="anchor" id="howtouse_generator"></a>

`Generator` generate LUA plugin based on JSON input given by the user.

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
The `Generator` does not perform any pre-validation on the user input. This is the role of the `Validator`. In case of invalid file, method from `Generator` will return appropriate `Err(WirdigenError)`. To avoid these kinds of problem, it's best to first perform a validation and, then, generate the LUA dissector.

`Generator` object also have a `from_value` method in order to reuse the serde-json `Value` from the validation task for the generation.

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

By default, the plugin is generated in the temporary folder defined in environment variable. The user can modify the output directory through `set_output_directory()` method and retrieve the current one through `get_output_directory()`.

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
The method `set_output_directory` does not create non-existant directory from user input.
If the output directory is not reachable, the error will be propagated from the generation method when trying to create the final LUA file.

# **Dissector format**

A JSON dissector description is composed of 4 elements:
- `name`
- `endianness`
- `connection`
- `data`

## **Name** <a class="anchor" id="dissector_name"></a>

`name` element is a string (max size: 32) representing the name of the protocol to dissect that  will be used inside Wireshark ("Protocol" column) to identify your packet.

**Note:** This name is also used for the generated LUA file. For example, if the attribute is `MY_PROTO`, the generated plugin will be called `dissector_MY_PROTO.lua`.

## **Endianness** <a class="anchor" id="dissector_endianness"></a>

String defining which endianness is used by the protocol.
Possible values are `little` and `big`.

## **Connection** <a class="anchor" id="dissector_connection"></a>

The `connection` object contains 2 fields :
- `protocol`: String. Either `udp` or `tcp`.
- `ports`: Array of port the dissector need to spy (between 1 and 65535).

## **Data** <a class="anchor" id="dissector_data"></a>

`data` is an array of object describing the packet. Each object define a chunk of the packet we want to identify.

Each chunk must contains the following attributes:
- `name`: String (max size: 32).
- `format`: String representing the data type of the chunk. Refer to format/base matrices below for available values.
- `base`: String representing how the value should be displayed. Refer to format/base matrices below for available values. 
- `offset`: Position offset, in byte, from the begining of the packet.
- `size`: Size, in byte, of the chunk inside the packet.

# **Format/Base compatibility matrices**

These matrices show which format/base combination are supported by Wirdigen. 

## **Numeric** <a class="anchor" id="matrix_numeric"></a>

| Format \ Base | NONE | DEC | OCT | HEX | DEC_HEX | HEX_DEC |
|:-------------:|:----:|:---:|:---:|:---:|:-------:|:-------:|
|      bool     |   X  |     |     |     |         |         |
|      char     |      |     |  X  |  X  |         |         |
|     uint8     |      |  X  |  X  |  X  |    X    |    X    |
|     uint16    |      |  X  |  X  |  X  |    X    |    X    |
|     uint24    |      |  X  |  X  |  X  |    X    |    X    |
|     uint32    |      |  X  |  X  |  X  |    X    |    X    |
|     uint64    |      |  X  |  X  |  X  |    X    |    X    |
|      int8     |      |  X  |     |     |         |         |
|     int16     |      |  X  |     |     |         |         |
|     int24     |      |  X  |     |     |         |         |
|     int32     |      |  X  |     |     |         |         |
|     int64     |      |  X  |     |     |         |         |
|    float(*)   |   X  |  X  |  X  |  X  |    X    |    X    |
|   double(*)   |   X  |  X  |  X  |  X  |    X    |    X    |

_(*) = For the specified `format`, the `base` is ignored by Wireshark._ 

## **Time** <a class="anchor" id="matrix_time"></a>

|   Format \ Base  | LOCAL | UTC | DOY_UTC |
|:----------------:|:-----:|:---:|:-------:|
|   absolute_time  |   X   |  X  |    X    |
| relative_time(*) |   X   |  X  |    X    |

_(*) = For the specified `format`, the `base` is ignored by Wireshark._

## **Raw** <a class="anchor" id="matrix_raw"></a>

| Format \ Base | NONE | DOT | DASH | COLON | SPACE |
|:-------------:|:----:|:---:|:----:|:-----:|:-----:|
|      byte     |   X  |  X  |   X  |   X   |   X   |

## **Specific** <a class="anchor" id="matrix_specific"></a>

For these specific type of data, display is automatically handled by Wirehsark. Hense, `base` is ignored. I would recommend using `NONE` in these case.

- none
- ipv4
- ipv6
- ether
- guid
- oid

# **Import dissector into Wireshark** <a class="anchor" id="import_dissector"></a>

First, you need to check in which directory Wireshark is looking for LUA plugin.

To do this, open Wireshark and go to `help -> About Wireshark -> Folder`.

Find the path associated to `"Personal Lua plugins"`. This is where you need to copy your dissector. If the path does not exist on your machine, you can manually create missing directories.

The dissector script will be active after Wireshark is refreshed. You can either restart Wireshark or press **Ctrl + Shift + L** to reload all Lua scripts.

**Note:** You need to reload/restart everytime you make a change in a dissector. 

# **Roadmap** <a class="anchor" id="roadmap"></a>

- Missing data type:
    - framenum
    - string
    - stringz
    - ubytes
    - protocol
    - rel_oid
    - systemid
    - eui64

- Extended atrtibute description
    - For a attribute, add the possibility for a user to specify a string description for specific value (eg: HTML - 404 -> NOT FOUND, 200 -> OK).

- Support for child subtree to clearly describe more complex packet.

- Thinking about potential support for array.
# Related tools <a class="anchor" id="related_tools"></a>

- [rust_dissector_generator](https://github.com/Cerclique/rust_dissector_generator): Simple executable using Wirdigen library
- [rust_dissector_udp](https://github.com/Cerclique/rust_dissector_udp): Send custom packet over UDP to test generated plugin by the library inside wireshark.
