#![feature(decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;

use rocket::request::{FlashMessage, Form};
use rocket::response::{Flash, Redirect};
use rocket_contrib::templates::Template;
use rocket_csrf::CsrfToken;

#[derive(Serialize)]
struct TemplateContext {
    authenticity_token: String,
    flash: Option<String>,
}

#[derive(FromForm)]
struct Comment {
    authenticity_token: String,
    text: String,
}

fn main() {
    rocket::ignite()
        .attach(rocket_csrf::Fairing::default())
        .attach(Template::fairing())
        .mount("/", routes![index, new, create])
        .launch();
}

#[get("/")]
fn index() -> Redirect {
    Redirect::to(uri!(new))
}

#[get("/comments/new")]
fn new(csrf_token: CsrfToken, flash: Option<FlashMessage>) -> Template {
    let template_context = TemplateContext {
        authenticity_token: csrf_token.authenticity_token().to_string(),
        flash: flash.map(|msg| format!("{}! {}", msg.name(), msg.msg())),
    };

    Template::render("comments/new", &template_context)
}

#[post("/comments", data = "<form>")]
fn create(csrf_token: CsrfToken, form: Form<Comment>) -> Flash<Redirect> {
    if let Err(_) = csrf_token.verify(&form.authenticity_token) {
        return Flash::error(Redirect::to(uri!(new)), "invalid authenticity token");
    }

    Flash::success(
        Redirect::to(uri!(new)),
        format!("created comment: {:#?}", form.text),
    )
}
