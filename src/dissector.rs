use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct Connection {
    /// Protocol to spy: TCP or UDP
    pub protocol: String,

    /// List of port to listen
    pub ports: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ValueString {
    /// Value to be replaced
    pub value: i64,

    /// String description of the value
    pub string: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DataChunk {
    /// Name of the attribute
    pub name: String,

    /// Data type of the attribute
    pub format: String,

    /// How the data should be displayed
    pub base: Option<String>,

    /// Size of the attribute
    pub size: Option<u32>,

    /// ValueString (Optional)
    pub valstr: Option<Vec<ValueString>>,

    /// DataChunk (Optional)
    pub subdata: Option<Vec<DataChunk>>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Dissector {
    /// Name of the dissector
    pub name: String,

    /// Big or little endian
    pub endianness: String,

    /// Network information
    pub connection: Connection,

    /// Packet description
    pub data: Vec<DataChunk>,
}
