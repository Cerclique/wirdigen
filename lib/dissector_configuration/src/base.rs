use strum::{Display, EnumIter, IntoEnumIterator};

#[derive(Debug, EnumIter, Display)]
pub enum Base {
    None,
    Dec,
    Hex,
    Oct,
    DecHex,
    HexDec,
    Utc,
    Local,
    DoyUtc,
    Dot,
    Dash,
    Colon,
    Space,
}

impl From<Option<String>> for Base {
    fn from(value: Option<String>) -> Self {
        if value.is_none() {
            return Base::None;
        }

        match value.unwrap().to_lowercase().as_str() {
            "none" => Base::None,
            "dec" => Base::Dec,
            "hex" => Base::Hex,
            "oct" => Base::Oct,
            "dec_hex" => Base::DecHex,
            "hex_dec" => Base::HexDec,
            "utc" => Base::Utc,
            "local" => Base::Local,
            "doy_utc" => Base::DoyUtc,
            "dot" => Base::Dot,
            "dash" => Base::Dash,
            "colon" => Base::Colon,
            "space" => Base::Space,
            _ => unreachable!(),
        }
    }
}

impl Base {
    pub fn get_values_as_string() -> Vec<String> {
        Self::iter().map(|x| format!("{}", x)).collect()
    }
}
