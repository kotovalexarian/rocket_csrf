use bcrypt::{hash, verify};
use rand::{distributions::Standard, Rng};
use rocket::{
    fairing::{Fairing as RocketFairing, Info, Kind},
    http::{Cookie, Status},
    request::{FromRequest, Outcome},
    Data, Request, Rocket, State,
};
use std::borrow::Cow;
use time::Duration;

const BCRYPT_COST: u32 = 8;

const _PARAM_NAME: &str = "authenticity_token";
const _HEADER_NAME: &str = "X-CSRF-Token";
const _PARAM_META_NAME: &str = "csrf-param";
const _TOKEN_META_NAME: &str = "csrf-token";

#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// CSRF Cookie lifespan
    lifespan: Duration,
    /// CSRF cookie name
    cookie_name: Cow<'static, str>,
    /// CSRF Token character length
    cookie_len: usize,
}

pub struct Fairing {
    config: CsrfConfig,
}

pub struct CsrfToken(String);

pub struct VerificationFailure;

impl Default for Fairing {
    fn default() -> Self {
        Self::new(CsrfConfig::default())
    }
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            /// Set to 6hour for default in Database Session stores.
            lifespan: Duration::days(1),
            cookie_name: "csrf_token".into(),
            cookie_len: 32,
        }
    }
}

impl Fairing {
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
}

impl CsrfToken {
    pub fn authenticity_token(&self) -> String {
        hash(&self.0, BCRYPT_COST).unwrap()
    }

    pub fn verify(&self, form_authenticity_token: &String) -> Result<(), VerificationFailure> {
        if verify(&self.0, form_authenticity_token).unwrap_or(false) {
            Ok(())
        } else {
            Err(VerificationFailure {})
        }
    }
}

impl RocketFairing for Fairing {
    fn info(&self) -> Info {
        Info {
            name: "CSRF",
            kind: Kind::Attach | Kind::Request,
        }
    }

    fn on_attach(&self, rocket: Rocket) -> std::result::Result<Rocket, Rocket> {
        Ok(rocket.manage(self.config.clone()))
    }

    fn on_request(&self, request: &mut Request, _: &Data) {
        let config = request.guard::<State<CsrfConfig>>().unwrap();

        if let Some(_) = request.valid_csrf_token_from_session(&config) {
            return;
        }

        let values: Vec<u8> = rand::thread_rng()
            .sample_iter(Standard)
            .take(config.cookie_len)
            .collect();

        let encoded = base64::encode(&values[..]);

        let now = time::now_utc() + config.lifespan;

        request.cookies().add_private(
            Cookie::build(config.cookie_name.clone(), encoded)
                .expires(now)
                .finish(),
        );
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for CsrfToken {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let config = request.guard::<State<CsrfConfig>>().unwrap();
        match request.valid_csrf_token_from_session(&config) {
            None => Outcome::Failure((Status::Forbidden, ())),
            Some(token) => Outcome::Success(Self(base64::encode(token))),
        }
    }
}

trait RequestCsrf {
    fn valid_csrf_token_from_session(&self, config: &CsrfConfig) -> Option<Vec<u8>> {
        self.csrf_token_from_session(config).and_then(|raw| {
            if raw.len() >= config.cookie_len {
                Some(raw)
            } else {
                None
            }
        })
    }

    fn csrf_token_from_session(&self, config: &CsrfConfig) -> Option<Vec<u8>>;
}

impl RequestCsrf for Request<'_> {
    fn csrf_token_from_session(&self, config: &CsrfConfig) -> Option<Vec<u8>> {
        self.cookies()
            .get_private(&config.cookie_name)
            .and_then(|cookie| base64::decode(cookie.value()).ok())
    }
}
