use std::path::PathBuf;

use libskyfall_macros::{handler, route};

#[derive(Clone, Debug)]
pub struct StaticFiles {
    pub paths: Vec<PathBuf>
}

#[handler(id = "core.static_files", prefix = "CORE_STATIC_FILES")]
impl StaticFiles {
    #[route(path = "/files/list")]
    pub async fn list_files(&self) -> anyhow::Result<()> {
        Ok(())
    }

    #[route(path = "/files/:path")]
    pub async fn get_file(&self, path: String) -> anyhow::Result<()> {
        Ok(())
    }
}