use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct Connection {
    pub protocol: String,
    pub ports: Vec<u16>
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DataChunck {
    pub name: String,
    pub format: String,
    pub filter_name: String,
    pub description: String,
    pub base: String,
    pub offset: u32,
    pub size: u32
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Dissector {
    pub name: String,
    pub connection: Connection,
    pub data: Vec<DataChunck>
}
