mod dissector;
pub mod error;
mod keyword;
mod utils;

use dissector::Dissector;
use error::{Error, Result};
use keyword::Keyword;

use std::env;
use std::fmt::Write as StringWrite;
use std::fs::File;
use std::io::{BufWriter, Read, Write as FileWrite};

use chrono::offset::Local;
use jsonschema::is_valid;
use serde_json::Value;

const DISSECTOR_TEMPLATE: &str = include_str!("../res/template.lua");
const JSON_SCHEMA: &str = include_str!("../res/schema.json");

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Wirdigen {
    output_dir: String,
    schema_value: Value,
}

/// Public.
impl Wirdigen {
    /// Create a Wirdigen object.
    pub fn new() -> Result<Wirdigen> {
        Ok(Wirdigen {
            output_dir: env::temp_dir().display().to_string(),
            schema_value: serde_json::from_str(JSON_SCHEMA)
                .map_err(Error::DeserializationFailed)?,
        })
    }

    /// Generate dissector plugin from an object implementing the `Read` trait (eg: BufReader).
    ///
    /// In case of success, return a `Result` containing the name of the file generated.
    pub fn generate_from_reader(&self, rdr: impl Read) -> Result<String> {
        let value: Value = serde_json::from_reader(rdr).map_err(Error::DeserializationFailed)?;

        self.run(value)
    }

    /// Generate dissector plugin from a `serde_json::Value`.
    ///
    /// In case of success, return a `Result` containing the name of the file generated.
    pub fn generate_from_value(&self, value: Value) -> Result<String> {
        self.run(value)
    }

    /// Try to validate the current dissector against a predefined schema.
    /// Return `true` is the current dissecord is valid, `false` otherwise.
    ///
    /// In case of error, details of each error are printed to `stderr`.
    pub fn try_validate(&self, value: &Value) -> bool {
        let schema =
            jsonschema::JSONSchema::compile(&self.schema_value).expect("Failed to compile schema.");

        let res = schema.validate(value);
        if let Err(errors) = res {
            for error in errors {
                eprintln!("Validation error: {error}");
                eprintln!("Instance path: {}", error.instance_path);
            }
            false
        } else {
            true
        }
    }

    /// Set path where dissectors are generated.
    pub fn set_output_directory(&mut self, dir_path: &str) {
        self.output_dir = dir_path.to_string();
    }

    /// Get current path where dissectors are generated.
    pub fn get_output_directory(&self) -> &str {
        self.output_dir.as_ref()
    }
}

/// Private
impl Wirdigen {
    fn run(&self, value: Value) -> Result<String> {
        if let true = is_valid(&self.schema_value, &value) {
            let dissector_value: Dissector =
                serde_json::from_value(value).map_err(Error::DeserializationFailed)?;

            // Perform generation.
            self.try_generate(dissector_value)
        } else {
            Err(Error::InvalidDissector("Failed to validate dissector. Try to perform `try_validate()` to ensure that the dissector is valid before the generation".to_string()))
        }
    }

    fn try_generate(&self, dissector: Dissector) -> Result<String> {
        // Load template from string constant.
        let mut output_buffer = String::from(DISSECTOR_TEMPLATE);

        // Project name
        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::ProjectName.as_str(),
            &format!("WIRDIGEN {VERSION}"),
        )?;

        // Dissector name
        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::DissectorName.as_str(),
            &dissector.name,
        )?;

        // Date
        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::Date.as_str(),
            &Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        )?;

        // Fields list
        // Fields declaration
        // Subtree population
        // ValueString

        let mut fields_list_buffer: String = String::new();
        let mut fields_declaration_buffer: String = String::new();
        let mut subtree_population_buffer: String = String::new();
        let mut valstr_buffer: String = String::new();

        let data_prefix: String = dissector.name.to_lowercase();

        // Variable to keep track of the current offset from the begining of the packet.
        let mut chunk_offset = 0;

        for chunk in dissector.data {
            let chunk_size = utils::get_chunk_size(&chunk.format).unwrap_or_else(|| {
                panic!(
                    "Unable to retrieve size for the current format: {}",
                    chunk.format
                )
            });

            let chunk_base = chunk
                .base
                .or(utils::get_default_base(&chunk.format))
                .unwrap_or_else(|| {
                    panic!(
                        "Unable to retrieve default base for the current format: {}",
                        chunk.format
                    )
                });

            // If `chunk.size` is equal to `None`, current chunk is a single element so an array of size 1.
            let chunk_array_length = chunk.size.unwrap_or(1);

            // This flag allow to build the `ValueString` object only one time in case of an array.
            let mut valstr_done = false;
            let mut valstr_name = String::new();

            let chunk_ref_name: &str = chunk.name.as_ref();
            for index in 0..chunk_array_length {
                let chunk_name = if chunk_array_length == 1 {
                    chunk_ref_name.to_string()
                } else {
                    format!("{chunk_ref_name}_{index}")
                };

                let full_filter_name: String = format!("{data_prefix}.{chunk_name}");

                // Check if 'valstr' is defined for current data chunk
                if let Some(valstr_vec) = chunk.valstr.as_ref() {
                    if !valstr_done {
                        let mut valstr_value_buffer: String = String::new();
                        for valstr_item in valstr_vec {
                            let _ = write!(
                                valstr_value_buffer,
                                "[{}] = \"{}\", ",
                                valstr_item.value, valstr_item.string
                            );
                        }

                        // Remove last whitespace and ','
                        valstr_value_buffer.truncate(valstr_value_buffer.chars().count() - 2);

                        valstr_name = format!("VALSTR_{}", chunk.name.to_uppercase());
                        let _ = writeln!(
                            valstr_buffer,
                            "local {valstr_name} = {{ {valstr_value_buffer} }}"
                        );

                        // Set flag to true to skip next interation for the current chunk.
                        valstr_done = true;
                    }

                    let _ = writeln!(
                        fields_declaration_buffer,
                        "local {} = ProtoField.{}(\"{}\", \"{}\", base.{}, {})",
                        chunk_name,
                        chunk.format,
                        full_filter_name,
                        chunk_name,
                        chunk_base,
                        valstr_name
                    );
                } else {
                    let _ = writeln!(
                        fields_declaration_buffer,
                        "local {} = ProtoField.{}(\"{}\", \"{}\", base.{})",
                        chunk_name, chunk.format, full_filter_name, chunk_name, chunk_base
                    );
                }

                let _ = write!(fields_list_buffer, "{chunk_name},\n\t");

                let add_endianness = if dissector.endianness == "little" {
                    "add_le"
                } else {
                    "add"
                };

                let buffer_declaration = format!("buffer({chunk_offset}, {chunk_size})");

                // Update offset.
                chunk_offset += chunk_size;

                let _ = write!(
                    subtree_population_buffer,
                    "subtree:{add_endianness}({chunk_name}, {buffer_declaration})\n\t"
                );
            }
        }

        fields_declaration_buffer.truncate(fields_declaration_buffer.chars().count() - 1);
        fields_list_buffer.truncate(fields_list_buffer.chars().count() - 2);

        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::FieldsList.as_str(),
            &fields_list_buffer,
        )?;

        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::ValueString.as_str(),
            &valstr_buffer,
        )?;

        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::FieldsDeclaration.as_str(),
            &fields_declaration_buffer,
        )?;

        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::SubtreePopulation.as_str(),
            &subtree_population_buffer,
        )?;

        output_buffer = utils::find_and_replace_all(
            &output_buffer,
            Keyword::Protocol.as_str(),
            &dissector.connection.protocol,
        )?;

        let mut ports_buffer: String = String::new();
        for port in dissector.connection.ports {
            let _ = writeln!(
                ports_buffer,
                "{}_port:add({}, {})",
                dissector.connection.protocol, port, dissector.name
            );
        }

        output_buffer =
            utils::find_and_replace_all(&output_buffer, Keyword::Ports.as_str(), &ports_buffer)?;

        let slash_platform = if cfg!(windows) {
            String::from("\\")
        } else {
            String::from("/")
        };

        let output_filename: String = format!(
            "{}{}dissector_{}.lua",
            self.output_dir, slash_platform, dissector.name
        );

        let output_file = File::create(&output_filename).map_err(Error::FileCreation)?;
        let mut f = BufWriter::new(output_file);
        f.write_all(output_buffer.as_bytes())
            .map_err(Error::FileWrite)?;

        Ok(output_filename)
    }
}
