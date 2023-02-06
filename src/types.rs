use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RsaPublicParts<'d> {
    pub n: &'d [u8],
    pub e: &'d [u8],
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RsaImportFormat<'d> {
    pub e: &'d [u8],
    pub p: &'d [u8],
    pub q: &'d [u8],
}
