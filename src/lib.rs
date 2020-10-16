use rand::RngCore;
use rocket::{Data, Request};
use rocket::fairing::{Fairing as RocketFairing, Info, Kind};
use rocket::http::{Cookie, Status};
use rocket::request::{FromRequest, Outcome};

const COOKIE_NAME: &str = "csrf_token";
const _PARAM_NAME: &str = "authenticity_token";
const _HEADER_NAME: &str = "X-CSRF-Token";
const _PARAM_META_NAME: &str = "csrf-param";
const _TOKEN_META_NAME: &str = "csrf-token";
const RAW_TOKEN_LENGTH: usize = 32;

pub struct Fairing;

pub struct Guard(pub String);

pub struct VerificationFailure;

impl Fairing {
    pub fn new() -> Self {
        Self {}
    }
}

impl Guard {
    pub fn verify(&self, form_authenticity_token: &String)
        -> Result<(), VerificationFailure>
    {
        if self.0 == *form_authenticity_token {
            Ok(())
        }
        else {
            Err(VerificationFailure {})
        }
    }
}

impl RocketFairing for Fairing {
    fn info(&self) -> Info {
        Info {
            name: "CSRF (Cross-Site Request Forgery) protection",
            kind: Kind::Request,
        }
    }

    fn on_request(&self, request: &mut Request, _: &Data) {
        if let Some(_) = request.valid_csrf_token_from_session() { return }

        let mut raw = [0u8; RAW_TOKEN_LENGTH];
        rand::thread_rng().fill_bytes(&mut raw);

        let encoded = base64::encode(raw);

        request.cookies().add_private(Cookie::new(COOKIE_NAME, encoded));
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for Guard {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        match request.valid_csrf_token_from_session() {
            None => Outcome::Failure((Status::Forbidden, ())),
            Some(token) => Outcome::Success(Self(base64::encode(token))),
        }
    }
}

trait RequestCsrf {
    fn valid_csrf_token_from_session(&self) -> Option<Vec<u8>> {
        self.csrf_token_from_session()
            .and_then(|raw|
                if raw.len() >= RAW_TOKEN_LENGTH { Some(raw) } else { None }
            )
    }

    fn csrf_token_from_session(&self) -> Option<Vec<u8>>;
}

impl RequestCsrf for Request<'_> {
    fn csrf_token_from_session(&self) -> Option<Vec<u8>> {
        self.cookies().get_private(COOKIE_NAME)
            .and_then(|cookie| base64::decode(cookie.value()).ok())
    }
}
