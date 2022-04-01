enum Keyword {
    ProjectName,
    DissectorName,
    Date,
    FieldsList,
    FieldsDeclaration,
    LocalVarDeclaration,
    SubtreePopulation,
    Protocol,
    Ports,
}

impl Keyword {
    fn as_str(&self) -> &'static str {
        match self {
            Self::ProjectName => "%PROJECT_NAME%",
            Self::DissectorName => "%DISSECTOR_NAME%",
            Self::Date => "%DATE%",
            Self::FieldsList => "%FIELDS_LIST%",
            Self::FieldsDeclaration => "%FIELDS_DECLARATION%",
            Self::LocalVarDeclaration => "%LOCAL_VAR_DECLARATION%",
            Self::SubtreePopulation => "%SUBTREE_POPULATION%",
            Self::Protocol => "%PROTOCOL%",
            Self::Ports => "%PORTS%",
        }
    }
}

#[cfg(test)] 
mod unit_test {
    use super::Keyword;

    #[test]
    fn keyword_as_str() {
        assert_eq!(Keyword::ProjectName.as_str(), "%PROJECT_NAME%");
        assert_eq!(Keyword::DissectorName.as_str(), "%DISSECTOR_NAME%");
        assert_eq!(Keyword::Date.as_str(), "%DATE%");
        assert_eq!(Keyword::FieldsList.as_str(), "%FIELDS_LIST%");
        assert_eq!(Keyword::FieldsDeclaration.as_str(), "%FIELDS_DECLARATION%");
        assert_eq!(Keyword::LocalVarDeclaration.as_str(), "%LOCAL_VAR_DECLARATION%");
        assert_eq!(Keyword::SubtreePopulation.as_str(), "%SUBTREE_POPULATION%");
        assert_eq!(Keyword::Protocol.as_str(), "%PROTOCOL%");
        assert_eq!(Keyword::Ports.as_str(), "%PORTS%");
    }
}