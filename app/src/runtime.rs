use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::bail;

use dissector_generator::generator::DissectorGenerator;
use dissector_parser::parsers::json::JSONParser;
use dissector_parser::traits::DissectorParsing;

use crate::error::Error;
use crate::file_format::FileFormat;

pub(crate) struct Runtime;

impl Runtime {
    pub(crate) fn run_check(input_path: &str) -> anyhow::Result<()> {
        match Path::new(input_path).extension().into() {
            FileFormat::Json => Self::check_impl::<JSONParser>(input_path),
            _ => bail!(Error::FileFormatNotSupported(String::from(input_path))),
        }
    }

    pub(crate) fn run_generate(input_path: &str, output_dir: Option<String>) -> anyhow::Result<()> {
        match Path::new(input_path).extension().into() {
            FileFormat::Json => Self::generate_impl::<JSONParser>(input_path, output_dir),
            _ => bail!(Error::FileFormatNotSupported(String::from(input_path))),
        }
    }
}

impl Runtime {
    fn load_input_file(input_path: &str) -> anyhow::Result<impl BufRead + Sized> {
        let file = File::open(input_path)
            .or_else(|e| bail!(Error::FileOpen(e, String::from(input_path))))?;

        Ok(BufReader::new(file))
    }

    fn check_impl<T: DissectorParsing>(input_path: &str) -> anyhow::Result<()> {
        let mut rdr = Self::load_input_file(input_path)?;

        T::check(&mut rdr)
            .map(|res| {
                if res.status {
                    println!("OK")
                } else {
                    println!("{}", res.message.unwrap())
                }
            })
            .or_else(|e| bail!(e))
    }

    fn generate_impl<T: DissectorParsing>(
        input_path: &str,
        output_dir: Option<String>,
    ) -> anyhow::Result<()> {
        let mut rdr = Self::load_input_file(input_path)?;

        let dissector_configuration = T::parse(&mut rdr)?;

        let _data = DissectorGenerator::generate(dissector_configuration, output_dir)?;

        todo!()
    }
}
