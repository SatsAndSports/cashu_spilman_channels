//! Axum route handlers for the ASCII art server.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::Engine;
use serde::Deserialize;

use cdk_spilman::axum::{configurable_management_router, SpilmanState};
use cdk_spilman::configurable_host::ConfigurableHost;
use cdk_spilman::configurable_networking::ReqwestNetworking;
use cdk_spilman::{ClosePreparationError, SpilmanBridge};

// ============================================================================
// Application State
// ============================================================================

pub type AppState = Arc<AppStateInner>;

pub struct AppStateInner {
    pub bridge: Arc<SpilmanBridge<ConfigurableHost>>,
    pub host: Arc<ConfigurableHost>,
    pub networking: Arc<ReqwestNetworking>,
    pub figlet_font: figlet_rs::FIGfont,
}

// ============================================================================
// Router
// ============================================================================

pub fn create_router(state: AppState) -> Router {
    let spilman_state = SpilmanState {
        bridge: state.bridge.clone(),
        host: state.host.clone(),
        networking: state.networking.clone(),
    };

    Router::new()
        // Business logic route
        .route("/ascii", post(post_ascii))
        .route("/ascii/preflight", post(preflight_ascii))
        // Nest standard Spilman management routes under /channel
        .nest("/channel", configurable_management_router(spilman_state))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Deserialize)]
pub struct AsciiRequest {
    pub message: String,
}

// ============================================================================
// POST /ascii
// ============================================================================

async fn post_ascii(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AsciiRequest>,
) -> Response {
    let payment_header_b64 = match headers.get("x-cashu-channel").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "Payment required",
                    "reason": "Missing X-Cashu-Channel header"
                })),
            )
                .into_response()
        }
    };

    let payment_json = match base64::engine::general_purpose::STANDARD.decode(payment_header_b64) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid payment header",
                    "reason": "invalid base64 encoding"
                })),
            )
                .into_response()
        }
    };

    // Context uses the same variable names as the YAML config.
    let context = serde_json::json!({ "chars": body.message.len() });

    match state
        .bridge
        .process_payment_via_json(&payment_json, &context.to_string())
    {
        Ok(success) => {
            // Calculate cost from config pricing.
            let unit = state
                .host
                .get_funding_data(&success.channel_id)
                .and_then(|f| {
                    serde_json::from_str::<serde_json::Value>(&f.params_json)
                        .ok()?
                        .get("unit")?
                        .as_str()
                        .map(String::from)
                })
                .unwrap_or_else(|| "sat".to_string());
            let scale = state.host.pricing_scale();
            let cost = state
                .host
                .config()
                .pricing
                .get(&unit)
                .and_then(|p| p.variables.get("chars"))
                .map(|&price| ((body.message.len() as u64) * price).div_ceil(scale))
                .unwrap_or(body.message.len() as u64);

            let art = state
                .figlet_font
                .convert(&body.message)
                .map(|f| f.to_string())
                .unwrap_or_else(|| body.message.clone());

            Json(serde_json::json!({
                "art": art,
                "message": body.message,
                "cost": cost,
                "payment": {
                    "channel_id": success.channel_id,
                    "balance": success.balance,
                    "amount_due": success.amount_due,
                    "capacity": success.capacity
                }
            }))
            .into_response()
        }
        Err(e) => {
            let error_response = ClosePreparationError::from_bridge_error(e);
            let status = match error_response.status {
                400 => StatusCode::BAD_REQUEST,
                402 => StatusCode::PAYMENT_REQUIRED,
                404 => StatusCode::NOT_FOUND,
                409 => StatusCode::CONFLICT,
                410 => StatusCode::GONE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": error_response.error,
                    "reason": error_response.reason
                })),
            )
                .into_response()
        }
    }
}

async fn preflight_ascii(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AsciiRequest>,
) -> Response {
    let payment_header_b64 = match headers.get("x-cashu-channel").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "Payment required",
                    "reason": "Missing X-Cashu-Channel header"
                })),
            )
                .into_response()
        }
    };

    let payment_json = match base64::engine::general_purpose::STANDARD.decode(payment_header_b64) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid payment header",
                    "reason": "invalid base64 encoding"
                })),
            )
                .into_response()
        }
    };

    let context = serde_json::json!({ "chars": body.message.len() });

    let ok = match state
        .bridge
        .payment_covers_amount_due_via_json(&payment_json, &context.to_string())
    {
        Ok(ok) => ok,
        Err(e) => {
            let error_response = ClosePreparationError::from_bridge_error(e);
            let status = match error_response.status {
                400 => StatusCode::BAD_REQUEST,
                402 => StatusCode::PAYMENT_REQUIRED,
                404 => StatusCode::NOT_FOUND,
                409 => StatusCode::CONFLICT,
                410 => StatusCode::GONE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return (
                status,
                Json(serde_json::json!({
                    "error": error_response.error,
                    "reason": error_response.reason
                })),
            )
                .into_response();
        }
    };

    if !ok {
        return Json(serde_json::json!({ "ok": false })).into_response();
    }

    match state
        .bridge
        .verify_payment_covers_amount_due_via_json(&payment_json, &context.to_string())
    {
        Ok(amount_due) => {
            Json(serde_json::json!({ "ok": true, "amount_due": amount_due })).into_response()
        }
        Err(e) => {
            let error_response = ClosePreparationError::from_bridge_error(e);
            let status = match error_response.status {
                400 => StatusCode::BAD_REQUEST,
                402 => StatusCode::PAYMENT_REQUIRED,
                404 => StatusCode::NOT_FOUND,
                409 => StatusCode::CONFLICT,
                410 => StatusCode::GONE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": error_response.error,
                    "reason": error_response.reason
                })),
            )
                .into_response()
        }
    }
}
