use strum::{Display, EnumIter, IntoEnumIterator};

#[derive(Debug, EnumIter, Display, Eq, PartialEq)]
pub enum Endianness {
    Little,
    Big,
}

impl From<String> for Endianness {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "little" => Endianness::Little,
            "big" => Endianness::Big,
            _ => unreachable!(),
        }
    }
}

impl Endianness {
    pub fn get_values_as_string() -> Vec<String> {
        Self::iter().map(|x| format!("{}", x)).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::endianness::Endianness;

    #[test]
    fn test_get_values_as_string_not_empty() {
        let list = Endianness::get_values_as_string();
        assert!(list.len() > 0)
    }

    #[test]
    #[should_panic]
    fn test_base_from_invalid_string() {
        let str = "InvalidString".to_string();
        let _ = Endianness::from(str);
    }
}
