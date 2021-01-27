use rand::{distributions::Standard, Rng};
use rocket::{
    fairing::{Fairing as RocketFairing, Info, Kind},
    http::{Cookie, Status},
    request::{FromRequest, Outcome},
    Data, Request, Rocket, State,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::borrow::Cow;
use time::Duration;

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

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            /// Set to 6hour for default in Database Session stores.
            lifespan: Duration::day(),
            cookie_name: "csrf_token".into(),
            cookie_len: 32,
        }
    }
}

pub struct Fairing {
    config: CsrfConfig,
}

pub struct CsrfToken(String);

pub struct VerificationFailure;

impl Fairing {
    pub fn new() -> Self {
        Self {
            config: Default::default(),
        }
    }

    /// Set CSRF lifetime (expiration time) for cookie.
    ///
    /// Call on the fairing before passing it to `rocket.attach()`
    pub fn with_lifetime(mut self, time: Duration) -> Self {
        self.config.lifespan = time;
        self
    }

    /// Set CSRF Cookie Name.
    ///
    /// Call on the fairing before passing it to `rocket.attach()`
    pub fn with_cookie_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.config.cookie_name = name.into();
        self
    }

    /// Set CSRF Cookie length, keep this above or equal to 16 in size.
    ///
    /// Call on the fairing before passing it to `rocket.attach()`
    pub fn with_cookie_len(mut self, length: usize) -> Self {
        let length = std::cmp::max(length, 16);
        self.config.cookie_len = length;
        self
    }

    /// Set CSRF Config from CsrfConfig
    ///
    /// Call on the fairing before passing it to `rocket.attach()`
    pub fn with_config(mut self, config: CsrfConfig) -> Self {
        self.config = config;
        self
    }
}

impl CsrfToken {
    pub fn authenticity_token(&self) -> String {
        hash(&self.0, DEFAULT_COST).unwrap()
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

        let values: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(config.cookie_len).collect();
        let encoded = base64::encode(&values[..]);

        request
            .cookies()
            .add_private(Cookie::new(config.cookie_name.clone(), encoded));
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
