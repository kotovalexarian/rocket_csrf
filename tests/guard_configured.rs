#[macro_use]
extern crate rocket;

use bcrypt::verify;
use rand::RngCore;
use rocket::http::Cookie;
use rocket_csrf::CsrfToken;

const COOKIE_NAME: &str = "foobar";
const COOKIE_LEN: usize = 64;

fn client() -> rocket::local::blocking::Client {
    rocket::local::blocking::Client::tracked(rocket()).unwrap()
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(rocket_csrf::Fairing::new(
            rocket_csrf::CsrfConfig::default()
                .with_cookie_name(COOKIE_NAME)
                .with_cookie_len(COOKIE_LEN)
                .with_lifetime(rocket::time::Duration::days(3)),
        ))
        .mount("/", routes![index])
}

#[get("/")]
fn index(csrf_token: CsrfToken) -> String {
    csrf_token.authenticity_token().to_string()
}

#[test]
fn respond_with_valid_authenticity_token() {
    let mut raw = [0u8; COOKIE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);

    let encoded = base64::encode(raw);

    let body = client()
        .get("/")
        .private_cookie(Cookie::new(COOKIE_NAME, encoded.to_string()))
        .dispatch()
        .into_string()
        .unwrap();

    assert!(verify(&encoded, &body).unwrap());
}
