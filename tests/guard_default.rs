#![feature(decl_macro)]

#[macro_use] extern crate rocket;

use rand::RngCore;
use rocket::http::Cookie;
use rocket_csrf::CsrfToken;
use bcrypt::verify;

fn client() -> rocket::local::Client {
    rocket::local::Client::new(rocket()).unwrap()
}

fn rocket() -> rocket::Rocket {
    rocket::ignite()
        .attach(rocket_csrf::Fairing::default())
        .mount("/", routes![index])
}

#[get("/")]
fn index(csrf_token: CsrfToken) -> String {
    csrf_token.authenticity_token().to_string()
}

#[test]
fn respond_with_valid_authenticity_token() {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);

    let encoded = base64::encode(raw);

    let body = client()
        .get("/")
        .private_cookie(Cookie::new("csrf_token", encoded.to_string()))
        .dispatch()
        .body()
        .unwrap()
        .into_string()
        .unwrap();

    assert!(verify(&encoded, &body).unwrap());
}
