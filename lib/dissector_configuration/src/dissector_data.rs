use crate::base::Base;
use crate::format::Format;

/// Data chunk description inside the payload
#[derive(Debug, Eq, PartialEq)]
pub struct Data {
    /// Name
    pub name: String,
    /// Format
    pub format: Format,
    /// Display base
    pub base: Base,
}

impl Data {
    pub fn new(name: String, format: Format, base: Base) -> Self {
        Self { name, format, base }
    }
}

#[cfg(test)]
mod tests {
    use crate::base::Base;
    use crate::dissector_data::Data;
    use crate::format::Format;

    #[test]
    fn test_data_new() {
        let name = "test_data".to_string();
        let format = Format::Char;
        let base = Base::DecHex;

        let data = Data::new(name, format, base);

        assert_eq!(data.name, "test_data");
        assert_eq!(data.format, Format::Char);
        assert_eq!(data.base, Base::DecHex);
    }
}
