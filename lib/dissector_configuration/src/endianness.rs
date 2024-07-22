use strum::{Display, EnumIter, IntoEnumIterator};

#[derive(Debug, EnumIter, Display)]
pub enum Endianness {
    LittleEndian,
    BigEndian,
}

impl From<String> for Endianness {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "little" => Endianness::LittleEndian,
            "big" => Endianness::BigEndian,
            _ => unreachable!(),
        }
    }
}

impl Endianness {
    pub fn get_values_as_string() -> Vec<String> {
        Self::iter().map(|x| format!("{}", x)).collect()
    }
}
