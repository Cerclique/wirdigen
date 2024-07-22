use strum::{Display, EnumIter, IntoEnumIterator};

#[derive(Debug, EnumIter, Display)]
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
