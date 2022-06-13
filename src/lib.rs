use constant_time_eq::constant_time_eq;
use rand::{distributions::Standard, Rng};
use rocket::{
    async_trait,
    fairing::{self, Fairing as RocketFairing, Info, Kind},
    http::{Cookie, Method, Status, uri},
    request::{FromRequest, Outcome},
    route::{self, Handler, Route},
    time::{Duration, OffsetDateTime},
    Data, Request, Rocket, State,
};
use std::borrow::Cow;

const COOKIE_NAME: &str = "csrf_token";
const _PARAM_NAME: &str = "authenticity_token";
const HEADER_NAME: &str = "X-CSRF-Token";
const _PARAM_META_NAME: &str = "csrf-param";
const _TOKEN_META_NAME: &str = "csrf-token";
const FORBIDDEN_ROUTE: &str = "/forbidden";

#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// CSRF Cookie lifespan
    lifespan: Duration,
    /// CSRF cookie name
    cookie_name: Cow<'static, str>,
    /// CSRF Token character length
    cookie_len: usize,
    /// Whether to use private cookies
    private_cookies: bool,
    /// CSRF header name
    header_name: Cow<'static, str>,
    /// URI for forbidden handler
    forbidden_uri: uri::Origin<'static>,
}

/// Fairing that sets the CSRF token cookie and verifies that write requests properly provide the
/// CSRF token via headers for AJAX requests or form data.
#[derive(Default)]
pub struct Fairing {
    token_fairing: TokenFairing,
}

/// Fairing that sets the CSRF token cookie.
pub struct TokenFairing {
    config: CsrfConfig,
}

pub struct CsrfToken(String);

pub struct VerificationFailure;

impl Default for TokenFairing {
    fn default() -> Self {
        Self::new(CsrfConfig::default())
    }
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            /// Set to 6hour for default in Database Session stores.
            lifespan: Duration::days(1),
            cookie_name: COOKIE_NAME.into(),
            cookie_len: 32,
            private_cookies: true,
            header_name: HEADER_NAME.into(),
            forbidden_uri: uri::Origin::parse(FORBIDDEN_ROUTE).unwrap(),
        }
    }
}

impl TokenFairing {
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }
}

impl CsrfConfig {
    /// Set CSRF lifetime (expiration time) for cookie.
    ///
    pub fn with_lifetime(mut self, time: Duration) -> Self {
        self.lifespan = time;
        self
    }

    /// Set CSRF Cookie Name.
    ///
    pub fn with_cookie_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Set CSRF Cookie length, keep this above or equal to 16 in size.
    ///
    pub fn with_cookie_len(mut self, length: usize) -> Self {
        self.cookie_len = length;
        self
    }

    /// Set whether CSRF Cookie is private.
    ///
    pub fn with_private_cookies(mut self, private: bool) -> Self {
        self.private_cookies = private;
        self
    }
}

impl CsrfToken {
    pub fn authenticity_token(self) -> String {
        self.0
    }

    pub fn verify(&self, form_authenticity_token: &String) -> Result<(), VerificationFailure> {
        // Constant time equality check.
        if constant_time_eq(&self.0.as_bytes(), form_authenticity_token.as_bytes()) {
            Ok(())
        } else {
            Err(VerificationFailure {})
        }
    }
}

fn is_write_request(request: &Request<'_>) -> bool {
    let method = request.method();
    [Method::Get, Method::Head, Method::Options, Method::Trace]
        .iter().any(|m| &method == m)
}

#[async_trait]
impl RocketFairing for Fairing {
    fn info(&self) -> Info {
        Info {
            name: "CSRF",
            kind: Kind::Ignite | Kind::Request,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<rocket::Build>) -> fairing::Result {
        // Set config.
        let rocket = self.token_fairing.on_ignite(rocket).await?;

        // Mount handle.
        let rank = None; // TODO
        let route = Route::ranked(rank, Method::Get, "/", ForbiddenHandler {});
        Ok(rocket.mount(self.token_fairing.config.forbidden_uri.clone(), [route]))
    }

    async fn on_request(&self, request: &mut Request<'_>, data: &mut Data<'_>) {
        // Set CSRF cookie.
        self.token_fairing.on_request(request, data).await;

        // Check if it's a write request.
        if !is_write_request(request) {
            return;
        }

        // Verify the provided CSRF token.
        // Return a forbidden status if it's invalid.
        let config = &self.token_fairing.config;
        if !verify_csrf_token(&request, &config).await {
            redirect_forbidden(request, &config).await;
        }
    }
}

async fn verify_csrf_token(request: &Request<'_>, config: &CsrfConfig) -> bool {
    // Get CSRF token from session cookie.
    if let Some(expected_token) = request.valid_csrf_token_from_session(&config) {
        // Get provided CSRF token from header or form data.
        if let Some(provided_token) = get_csrf_from_header(&request, &config)
                .or_else(|| get_csrf_from_form_data(&request, &config))
        {
            // Verify the provided token.
            match expected_token.verify(&provided_token) {
                Ok(()) => true,
                Err(VerificationFailure{}) => false,
            }
        } else {
            false
        }
    } else {
        false
    }
}

fn get_csrf_from_header(request: &Request<'_>, config: &CsrfConfig) -> Option<String> {
    // Get provided CSRF token from header.
    request.headers().get_one(&config.header_name).map(|t| t.to_string())
}

fn get_csrf_from_form_data(_request: &Request<'_>, _config: &CsrfConfig) -> Option<String> {
    // TODO: Parse form data and extract CSRF token.
    None
}

#[async_trait]
impl RocketFairing for TokenFairing {
    fn info(&self) -> Info {
        Info {
            name: "CSRF Token",
            kind: Kind::Ignite | Kind::Request,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<rocket::Build>) -> fairing::Result {
        Ok(rocket.manage(self.config.clone()))
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let config = &self.config;

        if let Some(_) = request.valid_csrf_token_from_session(&config) {
            return;
        }

        let values: Vec<u8> = rand::thread_rng()
            .sample_iter(Standard)
            .take(config.cookie_len)
            .collect();

        let encoded = base64::encode(&values[..]);

        let expires = OffsetDateTime::now_utc() + config.lifespan;

        let cookie = Cookie::build(config.cookie_name.clone(), encoded)
                    .expires(expires)
                    .finish();

        if config.private_cookies {
            request.cookies().add_private(cookie)
        } else {
            request.cookies().add(cookie)
        }
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for CsrfToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config = request.guard::<&State<CsrfConfig>>().await.unwrap();

        match request.valid_csrf_token_from_session(&config) {
            None => Outcome::Failure((Status::Forbidden, ())),
            Some(token) => Outcome::Success(token),
        }
    }
}

trait RequestCsrf {
    fn valid_csrf_token_from_session(&self, config: &CsrfConfig) -> Option<CsrfToken> {
        self.csrf_token_from_session(config).and_then(|raw| {
            if raw.len() >= config.cookie_len {
                Some(CsrfToken(raw))
            } else {
                None
            }
        })
    }

    fn csrf_token_from_session(&self, config: &CsrfConfig) -> Option<String>;
}

impl RequestCsrf for Request<'_> {
    fn csrf_token_from_session(&self, config: &CsrfConfig) -> Option<String> {
        let token = if config.private_cookies {
            self.cookies().get_private(&config.cookie_name)?.value().to_string()
        } else {
            self.cookies().get(&config.cookie_name)?.value().to_string()
        };

        Some(token)
    }
}

// Hack until [#749](https://github.com/SergioBenitez/Rocket/issues/749) is implemented.
async fn redirect_forbidden(request: &mut Request<'_>, config: &CsrfConfig) {
    let uri = config.forbidden_uri.clone();
    request.set_uri(uri);
    request.set_method(Method::Get);
}

#[derive(Clone)]
struct ForbiddenHandler {}

#[rocket::async_trait]
impl Handler for ForbiddenHandler {
    async fn handle<'a>(&self, _: &'a Request<'_>, _: Data<'a>) -> route::Outcome<'a> {
        route::Outcome::Failure(Status::Forbidden)
    }
}
