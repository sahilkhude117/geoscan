use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

pub(crate) struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn missing(entity: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{entity} was not found"),
        )
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Could not read or save scanner data",
        )
    }
}

impl From<geoscan_core::web::JobError> for ApiError {
    fn from(error: geoscan_core::web::JobError) -> Self {
        use geoscan_core::web::JobError;
        match error {
            JobError::Busy => Self::new(
                StatusCode::CONFLICT,
                "scanner_busy",
                "A scan is already running or the API is shutting down",
            ),
            JobError::NotFound => Self::missing("Job"),
            JobError::Database => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Could not read or save scanner data",
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response()
    }
}
