use std::fs::File;
use std::io::{Read, Write, BufWriter};
use serde_json::Value;
use regex::Regex;
use chrono::offset::Local;
use std::env;

use crate::dissector::Dissector;
use crate::keyword::Keyword;
use crate::template::DISSECTOR_TEMPLATE;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GeneratorError {
    #[error(transparent)]
    IOError (#[from] std::io::Error),

    #[error(transparent)]
    SerdeJsonError (#[from] serde_json::Error)
}

pub struct Generator {
    output_dir: String
}

impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl Generator {
    pub fn new() -> Generator {
        Generator { output_dir: env::temp_dir().display().to_string() }
    }
}

impl Generator {
    pub fn from_reader<R>(&self, rdr: R) -> Result<(), GeneratorError> where R : Read {
        let json_value: Value = serde_json::from_reader(rdr)?;
        self.run(json_value)?;
        Ok(())
    }

    pub fn from_value(&self, value: Value) -> Result<(), GeneratorError> {
        self.run(value)?;
        Ok(())
    }

    pub fn set_output_directory(&mut self, dir_path: &str) {
        self.output_dir = dir_path.to_string();
    }

    pub fn get_output_directory(&self) -> &str {
        &self.output_dir
    }
}

impl Generator {
    fn run(&self, value: Value) -> Result<(), GeneratorError> {
        let dissector: Dissector = serde_json::from_value(value)?;
        self.generate_dissector(dissector)?;
        Ok(())
    }

    fn generate_dissector(&self, dissector: Dissector) -> Result<(), GeneratorError> {
        // Load template from string constant
        let mut output_data: String = String::from(DISSECTOR_TEMPLATE);

        // Project name
        output_data =
            Self::find_and_replace_all(&output_data, Keyword::ProjectName.as_str(), "TODO");

        // Dissector name
        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::DissectorName.as_str(),
            &dissector.name,
        );

        // Date
        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::Date.as_str(),
            &Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );

        // Fields list
        // Fields declaration
        // Local variable declaration
        // Subtree population

        let mut fields_list_buffer = String::new();
        let mut fields_declaration_buffer = String::new();
        let mut local_var_declaration_buffer = String::new();
        let mut subtree_population_buffer = String::new();

        for data in dissector.data {
            let full_filter_name = format!("{}.{}", data.name, data.filter_name);

            fields_declaration_buffer.push_str(&format!(
                "{}=Protofield.{}(\"{}\", \"{}\", base.{})\n",
                data.filter_name, data.format, full_filter_name, data.description, data.base
            ));

            fields_list_buffer.push_str(&format!("{},\n\t", data.filter_name));

            local_var_declaration_buffer.push_str(&format!(
                "local{} = buffer({}, {})\n\t",
                data.filter_name, data.offset, data.size
            ));

            subtree_population_buffer
                .push_str(&format!("subtree:add({}, {})\n\t", data.filter_name, data.name));
        }

        fields_declaration_buffer.truncate(fields_declaration_buffer.chars().count() - 1);
        fields_list_buffer.truncate(fields_list_buffer.chars().count() - 2);
        local_var_declaration_buffer.truncate(local_var_declaration_buffer.chars().count() - 2);

        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::FieldsList.as_str(),
            &fields_list_buffer,
        );

        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::FieldsDeclaration.as_str(),
            &fields_declaration_buffer,
        );

        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::LocalVarDeclaration.as_str(),
            &local_var_declaration_buffer,
        );

        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::SubtreePopulation.as_str(),
            &subtree_population_buffer,
        );

        output_data = Self::find_and_replace_all(
            &output_data,
            Keyword::Protocol.as_str(),
            &dissector.connection.protocol,
        );

        let mut ports_buffer = String::new();
        for port in dissector.connection.ports {
            ports_buffer.push_str(&format!(
                "{}_port:add({}, {})\n",
                dissector.connection.protocol, port, dissector.name
            ));
        }

        output_data =
            Self::find_and_replace_all(&output_data, Keyword::Ports.as_str(), &ports_buffer);

        let output_filename: String = format!("{}/dissector_{}.lua", self.output_dir, dissector.name);

        let output_file = File::create(output_filename)?;
        let mut f = BufWriter::new(output_file);
        f.write_all(output_data.as_bytes())?;

        Ok(())
    }

    fn find_and_replace_all(buffer: &str, to_search: &str, to_replace: &str) -> String {
        let re = Regex::new(to_search).unwrap();
        re.replace_all(buffer, to_replace).to_string()
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;

    use std::io::BufReader;

    #[test]
    fn generator_find_and_replace_all() {
        let buffer: &str = "one two three one one";
        let to_search: &str = "one";
        let to_replace: &str = "zero";

        let expected: &str = "zero two three zero zero";

        assert_eq!(Generator::find_and_replace_all(buffer, to_search, to_replace), expected);
    }

    #[test]
    fn generator_set_output_directory() {
        let output_dir: &str = "/tmp/null";

        let mut gen = Generator::new();
        
        let expected = "/tmp";
        assert_eq!(gen.get_output_directory(), expected);

        gen.set_output_directory(output_dir);
        
        let expected = output_dir;
        assert_eq!(gen.get_output_directory(), expected);
    }

    #[test]
    fn generator_generate_dissector() -> Result<(), GeneratorError> {
        let file = File::open("./data/example_dissector.json")?;
        let rdr = BufReader::new(file);
        let value: Dissector = serde_json::from_reader(rdr)?;

        let gen = Generator::new();
        
        gen.generate_dissector(value)?;

        Ok(())
    }
}