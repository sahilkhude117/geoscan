//! Axum transport for the shared Rust scanner and background-job service.
mod error;
mod routes;

pub use geoscan_core::web::{
    AppState, Config, Job, ScanFuture, ScanRequest, ScanRunner, ScannerStatus,
};

pub fn router(state: AppState) -> axum::Router {
    routes::router(state)
}
