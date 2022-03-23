#[macro_use]
extern crate rocket;

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
                .with_lifetime(time::Duration::days(3)),
        ))
        .mount("/", routes![index])
}

#[get("/")]
fn index() {}

#[test]
fn add_csrf_token_to_cookies() {
    base64::decode(
        client()
            .get("/")
            .dispatch()
            .cookies()
            .iter()
            .find(|cookie| cookie.name() == COOKIE_NAME)
            .unwrap()
            .value(),
    )
    .unwrap();
}
