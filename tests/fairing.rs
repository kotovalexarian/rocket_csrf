#![feature(decl_macro)]

#[macro_use] extern crate rocket;

fn client() -> rocket::local::Client {
    rocket::local::Client::new(rocket()).unwrap()
}

fn rocket() -> rocket::Rocket {
    rocket::ignite()
        .attach(rocket_csrf::Fairing::new())
        .mount("/", routes![index])
}

#[get("/")]
fn index() {
}

#[test]
fn add_csrf_token_to_cookies() {
    base64::decode(client().get("/").dispatch().cookies().iter().find(|cookie| {
        cookie.name() == "csrf_token"
    }).unwrap().value()).unwrap();
}
