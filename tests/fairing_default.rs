#[macro_use]
extern crate rocket;

fn client() -> rocket::local::blocking::Client {
    rocket::local::blocking::Client::tracked(rocket()).unwrap()
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(rocket_csrf::Fairing::default())
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
            .find(|cookie| cookie.name() == "csrf_token")
            .unwrap()
            .value(),
    )
    .unwrap();
}
