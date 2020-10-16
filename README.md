rocket_csrf
===========

CSRF (Cross-Site Request Forgery) protection for Rocket web framework.

Usage
-----

Attach [fairing](https://rocket.rs/v0.4/guide/fairings/#fairings) to the Rocket
instance:

```rust
fn main() {
    rocket::ignite()
        .attach(rocket_csrf::Fairing::new())
        .mount("/", routes![/* your routes */)
        .launch();
}
```

Add [guard](https://rocket.rs/v0.4/guide/requests/#request-guards) to any
request where you want to have access to session's CSRF token (e.g. to include
it in forms) or verify it (e.g. to validate form):

```rust
#[get("/comments/new")]
fn index(csrf: rocket_csrf::Guard) -> Template {
    // your code
}

#[post("/comments", data = "<form>")]
fn create(csrf: rocket_csrf::Guard, form: Form<Comment>) -> Redirect {
    // your code
}
```

Get CSRF token from
[guard](https://rocket.rs/v0.4/guide/requests/#request-guards)
to use it in [templates](https://rocket.rs/v0.4/guide/responses/#templates):

```rust
#[get("/comments/new")]
fn index(csrf: rocket_csrf::Guard) -> Template {
    let csrf_token: String = csrf.0;

    // your code
}
```

Add CSRF token to your HTML forms in
[templates](https://rocket.rs/v0.4/guide/responses/#templates):

```html
<form method="post" action="/comments">
    <input type="hidden" name="authenticity_token" value="{{ csrf_token }}"/>
    <!-- your fields -->
</form>
```

Add attribute `authenticity_token` to your
[forms](https://rocket.rs/v0.4/guide/requests/#forms):

```rust
#[derive(FromForm)]
struct Comment {
    authenticity_token: String,
    // your attributes
}
```

Validate [forms](https://rocket.rs/v0.4/guide/requests/#forms) to have valid
authenticity token:

```rust
#[post("/comments", data = "<form>")]
fn create(csrf: rocket_csrf::Guard, form: Form<Comment>) -> Redirect {
    if Err(_) = csrf.verify(form.authenticity_token) {
        return Redirect::to(uri!(index));
    }

    // your code
}
```
