use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use axum::http::{HeaderMap, Method, Uri};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, Env, Secret};

const MAX_AUTH_FILE: u64 = 1024 * 1024;
const ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/version"),
    ("GET", "/version"),
    ("GET", "/v1/vpn/status"),
    ("PUT", "/v1/vpn/status"),
    ("GET", "/v1/vpn/settings"),
    ("PUT", "/v1/vpn/settings"),
    ("GET", "/v1/dns/status"),
    ("PUT", "/v1/dns/status"),
    ("GET", "/v1/updater/status"),
    ("PUT", "/v1/updater/status"),
    ("GET", "/v1/publicip/ip"),
    ("GET", "/unbound/actions/restart"),
    ("GET", "/updater/restart"),
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Policy {
    routes: BTreeMap<String, Vec<Authentication>>,
    fallback: Option<Authentication>,
    configured: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "auth", rename_all = "lowercase")]
enum Authentication {
    None,
    Apikey { apikey: Secret },
    Basic { username: Secret, password: Secret },
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    roles: Vec<Role>,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Role {
    name: String,
    auth: Option<AuthMethod>,
    apikey: Secret,
    username: Secret,
    password: Secret,
    routes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AuthMethod {
    None,
    Apikey,
    Basic,
}

impl Role {
    fn authentication(self) -> Result<Authentication, ConfigError> {
        if self.name.len() > 256 {
            return Err(ConfigError::Constraint(
                "control authentication role name exceeds 256 bytes".into(),
            ));
        }
        match self.auth {
            Some(AuthMethod::None) => Ok(Authentication::None),
            Some(AuthMethod::Apikey) if !self.apikey.is_empty() => Ok(Authentication::Apikey {
                apikey: self.apikey,
            }),
            Some(AuthMethod::Basic) if !self.username.is_empty() && !self.password.is_empty() => {
                Ok(Authentication::Basic {
                    username: self.username,
                    password: self.password,
                })
            }
            _ => Err(ConfigError::Constraint(
                "control authentication role requires a valid auth method and matching credentials"
                    .into(),
            )),
        }
    }
}

impl Policy {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let explicit_path = env.get("HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH");
        let path = PathBuf::from(explicit_path.unwrap_or("/gluetun/auth/config.toml"));
        let mut policy = Self::default();
        match std::fs::File::open(&path) {
            Ok(file) => {
                let mut contents = String::new();
                file.take(MAX_AUTH_FILE + 1)
                    .read_to_string(&mut contents)
                    .map_err(|source| ConfigError::ReadFile {
                        path: path.clone(),
                        source,
                    })?;
                if contents.len() as u64 > MAX_AUTH_FILE {
                    return Err(ConfigError::Constraint(
                        "control authentication file exceeds 1 MiB".into(),
                    ));
                }
                let config: FileConfig = toml::from_str(&contents).map_err(|_| {
                    ConfigError::Constraint("invalid control authentication TOML".into())
                })?;
                policy = Self::from_roles(config.roles)?;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && explicit_path.is_none() => {}
            Err(source) => return Err(ConfigError::ReadFile { path, source }),
        }
        if let Some(default) = env.get("HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE") {
            let role: Role = serde_json::from_str(default).map_err(|_| {
                ConfigError::Constraint("invalid control authentication default-role JSON".into())
            })?;
            if role.auth.is_some() {
                policy.fallback = Some(role.authentication()?);
                policy.configured = true;
            }
        }
        Ok(policy)
    }

    fn from_roles(roles: Vec<Role>) -> Result<Self, ConfigError> {
        let mut policy = Self {
            configured: true,
            ..Self::default()
        };
        for role in roles {
            for route in &role.routes {
                if !ROUTES
                    .iter()
                    .any(|(method, path)| route == &format!("{method} {path}"))
                {
                    return Err(ConfigError::Constraint(
                        "invalid route in control authentication role".into(),
                    ));
                }
            }
            let routes = role.routes.clone();
            let authentication = role.authentication()?;
            for route in routes {
                policy
                    .routes
                    .entry(route)
                    .or_default()
                    .push(authentication.clone());
            }
        }
        Ok(policy)
    }

    pub(super) fn authorized(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        legacy_key: &Secret,
    ) -> bool {
        let route = format!("{method} {}", uri.path());
        if let Some(roles) = self.routes.get(&route) {
            return roles.iter().any(|role| role.authorized(uri, headers));
        }
        if let Some(role) = &self.fallback {
            return role.authorized(uri, headers);
        }
        if self.configured {
            return false;
        }
        legacy_key.is_empty()
            || Authentication::Apikey {
                apikey: legacy_key.clone(),
            }
            .authorized(uri, headers)
    }
}

impl Authentication {
    fn authorized(&self, uri: &Uri, headers: &HeaderMap) -> bool {
        let authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        match self {
            Self::None => true,
            Self::Apikey { apikey } => {
                let query_key = uri
                    .query()
                    .and_then(|query| {
                        reqwest::Url::parse(&format!("http://localhost/?{query}")).ok()
                    })
                    .and_then(|url| {
                        url.query_pairs()
                            .find(|(key, _)| key == "api_key")
                            .map(|(_, value)| value.into_owned())
                    });
                let provided = headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .or_else(|| authorization.and_then(|value| value.strip_prefix("Bearer ")))
                    .or(query_key.as_deref());
                provided.is_some_and(|key| super::constant_time_equal(apikey.expose(), key))
            }
            Self::Basic { username, password } => {
                let decoded = authorization
                    .and_then(|value| value.strip_prefix("Basic "))
                    .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok());
                let Some(decoded) = decoded else {
                    return false;
                };
                let expected = format!("{}:{}", username.expose(), password.expose());
                std::str::from_utf8(&decoded)
                    .is_ok_and(|provided| super::constant_time_equal(&expected, provided))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        let config: FileConfig = toml::from_str(
            r#"
[[roles]]
name = "reader"
auth = "apikey"
apikey = "read-secret"
routes = ["GET /v1/vpn/status"]
[[roles]]
name = "operator"
auth = "basic"
username = "operator"
password = "secret"
routes = ["PUT /v1/vpn/status"]
[[roles]]
name = "public"
auth = "none"
routes = ["GET /v1/version"]
"#,
        )
        .expect("TOML");
        Policy::from_roles(config.roles).expect("roles")
    }

    #[test]
    fn roles_are_route_and_method_scoped_and_unassigned_routes_are_denied() {
        let policy = policy();
        let mut headers = HeaderMap::new();
        let status: Uri = "/v1/vpn/status".parse().expect("URI");
        let legacy = Secret::new("legacy-secret");
        assert!(!policy.authorized(&Method::GET, &status, &headers, &legacy));
        headers.insert("x-api-key", "read-secret".parse().expect("header"));
        assert!(policy.authorized(&Method::GET, &status, &headers, &legacy));
        assert!(!policy.authorized(&Method::PUT, &status, &headers, &legacy));
        headers.clear();
        headers.insert(
            "authorization",
            "Basic b3BlcmF0b3I6c2VjcmV0".parse().expect("header"),
        );
        assert!(policy.authorized(&Method::PUT, &status, &headers, &legacy));
        assert!(!policy.authorized(&Method::GET, &status, &headers, &legacy));
        assert!(!policy.authorized(
            &Method::GET,
            &"/v1/vpn/settings".parse().expect("URI"),
            &headers,
            &legacy
        ));
        headers.clear();
        assert!(policy.authorized(
            &Method::GET,
            &"/v1/version".parse().expect("URI"),
            &headers,
            &legacy
        ));
        assert!(policy.authorized(
            &Method::GET,
            &"/v1/vpn/status?api_key=read%2Dsecret".parse().expect("URI"),
            &headers,
            &legacy
        ));
        assert!(
            !serde_json::to_string(&policy)
                .expect("redacted")
                .contains("read-secret")
        );
        assert!(!format!("{policy:?}").contains("read-secret"));
    }

    #[test]
    fn malformed_roles_are_rejected_without_leaking_credentials() {
        for input in [
            r#"{"auth":"unknown","password":"secret-value"}"#,
            r#"{"auth":"apikey","apikey":""}"#,
            r#"{"auth":"basic","username":"user"}"#,
            r#"{"auth":"none","unknown":"secret-value"}"#,
        ] {
            let env = Env::from_pairs([("HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE", input)]);
            let error = Policy::from_env(&env).expect_err("invalid role");
            assert!(!error.to_string().contains("secret-value"));
        }
        let role = Role {
            auth: Some(AuthMethod::None),
            routes: vec!["GET /unknown".into()],
            ..Role::default()
        };
        assert!(Policy::from_roles(vec![role]).is_err());
        let env = Env::from_pairs([(
            "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE",
            r#"{"auth":"none"}"#,
        )]);
        let policy = Policy::from_env(&env).expect("default role");
        assert!(policy.authorized(
            &Method::GET,
            &"/v1/vpn/status".parse().expect("URI"),
            &HeaderMap::new(),
            &Secret::new("legacy")
        ));
    }
}
