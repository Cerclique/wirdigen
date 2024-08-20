use strum::{Display, EnumIter, IntoEnumIterator};

#[derive(Debug, EnumIter, Display, Eq, PartialEq)]
pub enum Protocol {
    Tcp = 0,
    Udp = 1,
}

impl From<String> for Protocol {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => unreachable!(),
        }
    }
}

impl Protocol {
    pub fn get_values_as_string() -> Vec<String> {
        Self::iter().map(|x| format!("{}", x)).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;

    #[test]
    fn test_get_values_as_string_not_empty() {
        let list = Protocol::get_values_as_string();
        assert!(list.len() > 0)
    }

    #[test]
    #[should_panic]
    fn test_base_from_invalid_string() {
        let str = "InvalidString".to_string();
        let _ = Protocol::from(str);
    }
}
