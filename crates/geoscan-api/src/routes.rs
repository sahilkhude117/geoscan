use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use geoscan_core::{
    catalog::{CveCheck, load_catalog},
    detect::{Detection, detect_geoserver, normalize_target},
    scan::{SUPPORTED_CHECKS, ScanReport, SqliTarget, read_scan_report},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;

use crate::{AppState, ScanRequest, error::ApiError};

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/checks", get(checks))
        .route("/api/v1/detect", post(detect))
        .route("/api/v1/scans", get(scans).post(start_scan))
        .route("/api/v1/scans/{id}", get(report))
        .route("/api/v1/jobs", get(job_list))
        .route("/api/v1/jobs/{id}", get(job))
        .fallback(|| async { ApiError::missing("API endpoint") })
        .method_not_allowed_fallback(|| async {
            ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "This HTTP method is not supported",
            )
        })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "api_version": "v1",
        "scanner": state.scanner(),
        "allowed_targets": state.allowed_targets(),
        "supported_checks": SUPPORTED_CHECKS,
        "catalog_entries": load_catalog().map(|catalog| catalog.len()).unwrap_or_default(),
        "max_active_scans": 1,
        "scan_timeout_seconds": 240,
        "defaults": {"sqli_layer": geoscan_core::scan::DEFAULT_LAYER, "sqli_property": geoscan_core::scan::DEFAULT_PROPERTY}
    }))
}

#[derive(Serialize)]
struct CatalogResponse {
    items: Vec<CveCheck>,
    supported_checks: &'static [&'static str],
}

async fn checks() -> Result<Json<CatalogResponse>, ApiError> {
    let items = load_catalog().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "catalog_error",
            "Could not load the CVE catalogue",
        )
    })?;
    Ok(Json(CatalogResponse {
        items,
        supported_checks: SUPPORTED_CHECKS,
    }))
}

fn input<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    body.map(|Json(value)| value).map_err(|error| {
        // Parser diagnostics can quote request values, including passwords.
        ApiError::new(
            error.status(),
            "invalid_json",
            "Provide a valid application/json body with the documented fields and types",
        )
    })
}

fn validate(state: &AppState, request: &mut ScanRequest) -> Result<(), ApiError> {
    if request.target.len() > 2048 {
        return Err(ApiError::invalid("Target URL is too long"));
    }
    request.target = normalize_target(&request.target)
        .map_err(|_| ApiError::invalid("Provide a complete HTTP(S) application URL without credentials, query, or fragment"))?
        .to_string();
    if !state.allowed_targets().contains(&request.target) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "target_not_allowed",
            "Target is not in the backend's configured allowed targets",
        ));
    }
    match (&request.username, &request.password) {
        (None, None) => {}
        (Some(username), Some(password))
            if !username.trim().is_empty()
                && !password.is_empty()
                && username.len() <= 256
                && password.len() <= 4096 => {}
        _ => {
            return Err(ApiError::invalid(
                "Supply both username and password, or omit both",
            ));
        }
    }
    SqliTarget::new(&request.sqli_layer, &request.sqli_property).map_err(ApiError::invalid)?;
    Ok(())
}

async fn detect(
    State(state): State<AppState>,
    body: Result<Json<ScanRequest>, JsonRejection>,
) -> Result<Json<Detection>, ApiError> {
    let mut request = input(body)?;
    validate(&state, &mut request)?;
    let auth = request.username.as_deref().zip(request.password.as_deref());
    let detection = detect_geoserver(&request.target, auth).await.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "detection_failed",
            "Could not check the configured GeoServer target",
        )
    })?;
    Ok(Json(detection))
}

async fn start_scan(
    State(state): State<AppState>,
    body: Result<Json<ScanRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let mut request = input(body)?;
    validate(&state, &mut request)?;
    let job = state.submit(request).await?;
    let location = format!("/api/v1/jobs/{}", job.id);
    Ok((
        StatusCode::ACCEPTED,
        [(header::LOCATION, location)],
        Json(job),
    )
        .into_response())
}

fn positive_id(id: &str) -> Result<i64, ApiError> {
    id.parse()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| ApiError::invalid("ID must be a positive integer"))
}

async fn job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::Job>, ApiError> {
    Ok(Json(state.job(positive_id(&id)?).await?))
}

async fn report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScanReport>, ApiError> {
    let id = positive_id(&id)?;
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM scans WHERE id=?")
        .bind(id)
        .fetch_optional(state.pool())
        .await?;
    match status.as_deref() {
        None => return Err(ApiError::missing("Scan")),
        Some("running") => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "scan_running",
                "This report is still being written; poll the job",
            ));
        }
        _ => {}
    }
    let report = read_scan_report(state.database(), Some(id))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "report_error",
                "Could not read the saved report",
            )
        })?;
    Ok(Json(report))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pagination {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    25
}

fn pagination(query: Result<Query<Pagination>, QueryRejection>) -> Result<Pagination, ApiError> {
    let Query(page) = query
        .map_err(|_| ApiError::invalid("Provide integer limit and offset query parameters"))?;
    if !(1..=100).contains(&page.limit) || page.offset < 0 {
        return Err(ApiError::invalid(
            "limit must be 1–100; offset must be zero or greater",
        ));
    }
    Ok(page)
}

async fn scans(
    State(state): State<AppState>,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let page = pagination(query)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM scans")
        .fetch_one(state.pool())
        .await?;
    let rows = sqlx::query(
        "SELECT scans.id, target, geoserver_version, status, started_at, finished_at,
        (SELECT count(*) FROM findings WHERE findings.scan_id=scans.id) AS finding_count
        FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(page.limit)
    .bind(page.offset)
    .fetch_all(state.pool())
    .await?;
    let items: Vec<Value> = rows.into_iter().map(|row| json!({
        "id": row.get::<i64,_>("id"), "target": row.get::<String,_>("target"),
        "geoserver_version": row.get::<Option<String>,_>("geoserver_version"),
        "status": row.get::<String,_>("status"), "started_at": row.get::<String,_>("started_at"),
        "finished_at": row.get::<Option<String>,_>("finished_at"), "finding_count": row.get::<i64,_>("finding_count")
    })).collect();
    Ok(Json(
        json!({"items":items, "total":total, "limit":page.limit, "offset":page.offset}),
    ))
}

async fn job_list(
    State(state): State<AppState>,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let page = pagination(query)?;
    let (items, total) = state.jobs(page.limit, page.offset).await?;
    Ok(Json(
        json!({"items": items, "total": total, "limit":page.limit, "offset":page.offset}),
    ))
}
