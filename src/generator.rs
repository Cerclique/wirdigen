//! Module to generate LUA plugin from JSON of a dissector

use chrono::offset::Local;
use regex::Regex;
use serde_json::Value;
use std::env;
use std::fmt::Write as StringWrite;
use std::fs::File;
use std::io::Write as FileWrite;
use std::io::{BufWriter, Read};

use crate::dissector::Dissector;
use crate::error::WirdigenError;
use crate::keyword::Keyword;
use crate::template::DISSECTOR_TEMPLATE;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Generator {
    output_dir: String,
}

impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl Generator {
    /// Create a new generator object
    pub fn new() -> Generator {
        Generator {
            output_dir: env::temp_dir().display().to_string(),
        }
    }
}

impl Generator {
    /// Try to generate LUA plugin from a reader
    pub fn from_reader<R>(&self, rdr: R) -> Result<String, WirdigenError>
    where
        R: Read,
    {
        let dissector_value: Dissector = serde_json::from_reader(rdr)?;
        self.generate_dissector(dissector_value)
    }

    /// Try to generate LUA plugin from a serde_json value
    pub fn from_value(&self, value: Value) -> Result<String, WirdigenError> {
        let dissector: Dissector = serde_json::from_value(value)?;
        self.generate_dissector(dissector)
    }

    /// Set the output directory where plugin are generated.
    ///
    /// Note: This function does not create non-existent directory
    pub fn set_output_directory(&mut self, dir_path: &str) {
        self.output_dir = dir_path.to_string();
    }

    /// Get current output directory of generated directory
    ///
    /// Note: By default, the value is set to the temporary directory of the OS
    pub fn get_output_directory(&self) -> &str {
        &self.output_dir
    }
}

impl Generator {
    fn generate_dissector(&self, dissector: Dissector) -> Result<String, WirdigenError> {
        // Load template from string constant
        let mut output_data: String = String::from(DISSECTOR_TEMPLATE);

        let tool_name = format!("WIRDIGEN {}", VERSION);
        // Project name
        output_data =
            self.find_and_replace_all(&output_data, Keyword::ProjectName.as_str(), &tool_name)?;

        // Dissector name
        output_data = self.find_and_replace_all(
            &output_data,
            Keyword::DissectorName.as_str(),
            &dissector.name,
        )?;

        // Date
        output_data = self.find_and_replace_all(
            &output_data,
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

        let data_prefix_name: String = dissector.name.to_lowercase();

        for data in dissector.data {
            let full_filter_name: String = format!("{}.{}", data_prefix_name, data.name);

            // Check if 'valstr' is defined for current data chunk
            if let Some(valstr_vec) = data.valstr {
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

                let valstr_name = format!("VALSTR_{}", data.name.to_uppercase());
                let _ = writeln!(
                    valstr_buffer,
                    "local {} = {{ {} }}",
                    valstr_name, valstr_value_buffer
                );

                let _ = writeln!(
                    fields_declaration_buffer,
                    "local {} = ProtoField.{}(\"{}\", \"{}\", base.{}, {})",
                    data.name, data.format, full_filter_name, data.name, data.base, valstr_name
                );
            } else {
                let _ = writeln!(
                    fields_declaration_buffer,
                    "local {} = ProtoField.{}(\"{}\", \"{}\", base.{})",
                    data.name, data.format, full_filter_name, data.name, data.base
                );
            }

            let _ = write!(fields_list_buffer, "{},\n\t", data.name);

            let add_endianness = if dissector.endianness == "little" {
                String::from("add_le")
            } else {
                String::from("add")
            };

            let buffer_declaration: String = format!("buffer({}, {})", data.offset, data.size);

            let _ = write!(
                subtree_population_buffer,
                "subtree:{}({}, {})\n\t",
                add_endianness, data.name, buffer_declaration
            );
        }

        fields_declaration_buffer.truncate(fields_declaration_buffer.chars().count() - 1);
        fields_list_buffer.truncate(fields_list_buffer.chars().count() - 2);

        output_data = self.find_and_replace_all(
            &output_data,
            Keyword::FieldsList.as_str(),
            &fields_list_buffer,
        )?;

        output_data =
            self.find_and_replace_all(&output_data, Keyword::ValueString.as_str(), &valstr_buffer)?;

        output_data = self.find_and_replace_all(
            &output_data,
            Keyword::FieldsDeclaration.as_str(),
            &fields_declaration_buffer,
        )?;

        output_data = self.find_and_replace_all(
            &output_data,
            Keyword::SubtreePopulation.as_str(),
            &subtree_population_buffer,
        )?;

        output_data = self.find_and_replace_all(
            &output_data,
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

        output_data =
            self.find_and_replace_all(&output_data, Keyword::Ports.as_str(), &ports_buffer)?;

        let slash_platform: String = if cfg!(windows) {
            String::from("\\")
        } else {
            String::from("/")
        };

        let output_filename: String = format!(
            "{}{}dissector_{}.lua",
            self.output_dir, slash_platform, dissector.name
        );

        let output_file = File::create(&output_filename)?;
        let mut f = BufWriter::new(output_file);
        f.write_all(output_data.as_bytes())?;
        Ok(output_filename)
    }

    fn find_and_replace_all(
        &self,
        buffer: &str,
        to_search: &str,
        to_replace: &str,
    ) -> Result<String, WirdigenError> {
        let re = Regex::new(to_search)?;
        Ok(re.replace_all(buffer, to_replace).to_string())
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;

    use std::io::BufReader;

    #[test]
    fn generator_default() {
        let _ = Generator::default();
    }

    #[test]
    fn generator_find_and_replace_all() -> Result<(), WirdigenError> {
        let buffer: &str = "one two three one one";
        let to_search: &str = "one";
        let to_replace: &str = "zero";

        let expected: &str = "zero two three zero zero";

        let result = Generator::default().find_and_replace_all(buffer, to_search, to_replace)?;

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn generator_from_reader() -> Result<(), WirdigenError> {
        let file = File::open("./example/example_dissector.json")?;
        let rdr = BufReader::new(file);

        let output_file_path = Generator::default().from_reader(rdr)?;
        println!("{}", output_file_path);

        Ok(())
    }

    #[test]
    fn generator_from_value() -> Result<(), WirdigenError> {
        let file = File::open("./example/example_dissector.json")?;
        let rdr = BufReader::new(file);
        let value: Value = serde_json::from_reader(rdr)?;

        let output_file_path = Generator::default().from_value(value)?;
        println!("{}", output_file_path);

        Ok(())
    }

    #[test]
    fn generator_set_output_directory() {
        let mut gen = Generator::default();

        let expected = env::temp_dir().display().to_string();
        assert_eq!(gen.get_output_directory(), expected);

        let new_output_dir = format!("{}/toast", expected);
        gen.set_output_directory(&new_output_dir);

        let expected = new_output_dir;
        assert_eq!(gen.get_output_directory(), expected);
    }
}
