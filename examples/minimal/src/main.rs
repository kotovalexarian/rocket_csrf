#![feature(decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate serde_derive;

use rocket::response::Redirect;
use rocket::request::Form;
use rocket_contrib::templates::Template;

#[derive(Serialize)]
struct TemplateContext {
    csrf_token: String,
}

#[derive(FromForm)]
struct Comment {
    authenticity_token: String,
    text: String,
}

fn main() {
    rocket::ignite()
        .attach(rocket_csrf::Fairing::new())
        .attach(Template::fairing())
        .mount("/", routes![new, create])
        .launch();
}

#[get("/comments/new")]
fn new(csrf: rocket_csrf::Guard) -> Template {
    let template_context = TemplateContext {
        csrf_token: csrf.0,
    };

    Template::render("comments/new", &template_context)
}

#[post("/comments", data = "<form>")]
fn create(csrf: rocket_csrf::Guard, form: Form<Comment>) -> Redirect {
    if let Err(_) = csrf.verify(&form.authenticity_token) {
        return Redirect::to(uri!(new));
    }

    Redirect::to(uri!(new))
}
