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
