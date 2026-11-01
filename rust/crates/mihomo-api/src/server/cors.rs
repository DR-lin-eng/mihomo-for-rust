use super::{ApiHttpRequest, ApiHttpResponse, RuntimeConfigDocument};

#[derive(Clone, Debug)]
pub(super) struct ControllerCors {
    origins: Vec<String>,
    private_network: bool,
}

impl ControllerCors {
    pub(super) fn from_document(document: &RuntimeConfigDocument) -> Self {
        let raw = document
            .extra
            .get("external-controller-cors")
            .and_then(|v| v.as_mapping());
        let get = |key: &str| raw.and_then(|map| map.get(serde_yaml::Value::String(key.into())));
        Self {
            origins: get("allow-origins")
                .and_then(|v| v.as_sequence())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_else(|| vec!["*".into()]),
            private_network: get("allow-private-network")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        }
    }

    fn allowed(&self, origin: &str) -> bool {
        self.origins.iter().any(|pattern| {
            if pattern == "*" || pattern == origin {
                return true;
            }
            if let Some((before, after)) = pattern.split_once('*') {
                return origin.starts_with(before)
                    && origin.ends_with(after)
                    && origin.len() >= before.len() + after.len();
            }
            false
        })
    }

    pub(super) fn apply(&self, request: &ApiHttpRequest, response: &mut ApiHttpResponse) {
        let Some(origin) = request.header("origin") else {
            return;
        };
        response.headers.insert("Vary".into(), "Origin".into());
        if self.allowed(origin) {
            let allowed = if self.origins.iter().any(|value| value == "*") {
                "*"
            } else {
                origin
            };
            response
                .headers
                .insert("Access-Control-Allow-Origin".into(), allowed.into());
        }
    }

    pub(super) fn preflight(&self, request: &ApiHttpRequest) -> Option<ApiHttpResponse> {
        if !request.method.eq_ignore_ascii_case("OPTIONS") {
            return None;
        }
        let mut response = ApiHttpResponse {
            status_code: 204,
            headers: Default::default(),
            body: Vec::new(),
        };
        self.apply(request, &mut response);
        let origin_allowed = request
            .header("origin")
            .is_some_and(|origin| self.allowed(origin));
        let method_allowed =
            request
                .header("access-control-request-method")
                .is_some_and(|method| {
                    matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE")
                });
        let headers_allowed = request
            .header("access-control-request-headers")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .all(|h| {
                h.eq_ignore_ascii_case("authorization") || h.eq_ignore_ascii_case("content-type")
            });
        if origin_allowed && method_allowed && headers_allowed {
            response.headers.insert(
                "Access-Control-Allow-Methods".into(),
                "GET, HEAD, POST, PUT, PATCH, DELETE".into(),
            );
            response.headers.insert(
                "Access-Control-Allow-Headers".into(),
                "Authorization, Content-Type".into(),
            );
            response
                .headers
                .insert("Access-Control-Max-Age".into(), "300".into());
            if self.private_network
                && request.header("access-control-request-private-network") == Some("true")
            {
                response
                    .headers
                    .insert("Access-Control-Allow-Private-Network".into(), "true".into());
            }
        }
        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dashboard_preflight_precedes_secret_auth_and_advertises_private_network() {
        let document =
            mihomo_config::parse_runtime_config_document("secret: test-secret\n").unwrap();
        let controller = super::super::ApiController::from_document(&document).unwrap();
        let request = ApiHttpRequest {
            method: "OPTIONS".into(),
            target: "/configs".into(),
            ..Default::default()
        }
        .with_header("Origin", "http://router.lan")
        .with_header("Access-Control-Request-Method", "PATCH")
        .with_header(
            "Access-Control-Request-Headers",
            "authorization,content-type",
        )
        .with_header("Access-Control-Request-Private-Network", "true");
        let response = controller.handle_request(&request);
        assert_eq!(response.status_code, 204);
        assert_eq!(response.headers["Access-Control-Allow-Origin"], "*");
        assert_eq!(
            response.headers["Access-Control-Allow-Private-Network"],
            "true"
        );
        let denied = controller.handle_request(
            &ApiHttpRequest::get("/configs").with_header("Origin", "http://router.lan"),
        );
        assert_eq!(denied.status_code, 401);
        assert_eq!(denied.headers["Access-Control-Allow-Origin"], "*");
    }

    #[test]
    fn configured_origin_list_does_not_advertise_access_to_unlisted_dashboard() {
        let document = mihomo_config::parse_runtime_config_document("external-controller-cors:\n  allow-origins: [https://*.example.com]\n  allow-private-network: false\n").unwrap();
        let cors = ControllerCors::from_document(&document);
        let mut response = ApiHttpResponse {
            status_code: 200,
            headers: Default::default(),
            body: vec![],
        };
        cors.apply(
            &ApiHttpRequest::get("/version").with_header("Origin", "https://bad.test"),
            &mut response,
        );
        assert!(!response.headers.contains_key("Access-Control-Allow-Origin"));
        cors.apply(
            &ApiHttpRequest::get("/version").with_header("Origin", "https://panel.example.com"),
            &mut response,
        );
        assert_eq!(
            response.headers["Access-Control-Allow-Origin"],
            "https://panel.example.com"
        );
    }
}
