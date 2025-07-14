mod routes;
pub use routes::*;

use tauri::Manager;
use taurpc::Router;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let router = Router::new().export_config(
        specta_typescript::Typescript
            ::default()
            .formatter(specta_typescript::formatter::prettier)
            .bigint(specta_typescript::BigIntExportBehavior::BigInt)
    );

    tauri::Builder
        ::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_single_instance::init(|app, _, _| {
                let _ = app.get_webview_window("main").expect("no main window").set_focus();
            })
        )
        .plugin(tauri_plugin_persisted_scope::init())
        .plugin(tauri_plugin_fs::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
