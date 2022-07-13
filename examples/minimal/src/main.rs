#![feature(decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;

use rocket::form::Form;
use rocket::request::FlashMessage;
use rocket::response::{Flash, Redirect};
use rocket_csrf::CsrfToken;
use rocket_dyn_templates::Template;

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

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(rocket_csrf::Fairing::default())
        .attach(Template::fairing())
        .mount("/", routes![index, new, create])
}

#[get("/")]
fn index() -> Redirect {
    Redirect::to(uri!(new))
}

#[get("/comments/new")]
fn new(csrf_token: CsrfToken, flash: Option<FlashMessage>) -> Template {
    let template_context = TemplateContext {
        authenticity_token: csrf_token.authenticity_token().to_string(),
        flash: flash.map(|flash| flash.message().to_string()),
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
