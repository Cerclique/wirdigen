pub(crate) enum Keyword {
    Date,
    DissectorName,
    FieldsDeclaration,
    FieldsList,
    Ports,
    ProjectName,
    Protocol,
    SubtreePopulation,
    ValueString,
}

impl Keyword {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Date => "%DATE%",
            Self::DissectorName => "%DISSECTOR_NAME%",
            Self::FieldsDeclaration => "%FIELDS_DECLARATION%",
            Self::FieldsList => "%FIELDS_LIST%",
            Self::Ports => "%PORTS%",
            Self::ProjectName => "%PROJECT_NAME%",
            Self::Protocol => "%PROTOCOL%",
            Self::SubtreePopulation => "%SUBTREE_POPULATION%",
            Self::ValueString => "%VALUESTRING_DECLARATION%",
        }
    }
}

#[cfg(test)]
mod unit_test {
    use super::Keyword;

    #[test]
    fn keyword_as_str() {
        assert_eq!(Keyword::Date.as_str(), "%DATE%");
        assert_eq!(Keyword::DissectorName.as_str(), "%DISSECTOR_NAME%");
        assert_eq!(Keyword::FieldsDeclaration.as_str(), "%FIELDS_DECLARATION%");
        assert_eq!(Keyword::FieldsList.as_str(), "%FIELDS_LIST%");
        assert_eq!(Keyword::Ports.as_str(), "%PORTS%");
        assert_eq!(Keyword::ProjectName.as_str(), "%PROJECT_NAME%");
        assert_eq!(Keyword::Protocol.as_str(), "%PROTOCOL%");
        assert_eq!(Keyword::SubtreePopulation.as_str(), "%SUBTREE_POPULATION%");
        assert_eq!(Keyword::ValueString.as_str(), "%VALUESTRING_DECLARATION%")
    }
}
