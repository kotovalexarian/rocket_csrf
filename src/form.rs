use rocket::{
    async_trait,
    data::{Data, FromData, Outcome},
    form::{Error, Form, FromForm},
    http::Status,
    Request,
};

use crate::CsrfToken;

pub struct CsrfForm<T>(T);

impl<T> std::ops::Deref for CsrfForm<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub enum CsrfError<E> {
    CSRFTokenInvalid,
    Other(E),
}

struct CsrfTokenForm<'r, T> {
    token: &'r str,
    inner: T,
}

impl<'r, T: FromForm<'r>> FromForm<'r> for CsrfTokenForm<'r, T> {
    type Context = (Option<&'r str>, T::Context);
    fn init(opts: rocket::form::Options) -> Self::Context {
        (None, T::init(opts))
    }

    fn push_value(ctxt: &mut Self::Context, field: rocket::form::ValueField<'r>) {
        if field.name == "csrf_token" {
            ctxt.0 = Some(field.value);
        } else {
            T::push_value(&mut ctxt.1, field);
        }
    }

    fn push_data<'life0, 'life1, 'async_trait>(
        ctxt: &'life0 mut Self::Context,
        field: rocket::form::DataField<'r, 'life1>,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = ()> + core::marker::Send + 'async_trait>,
    >
    where
        'r: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        T::push_data(&mut ctxt.1, field)
    }

    fn finalize(ctxt: Self::Context) -> rocket::form::Result<'r, Self> {
        let inner = T::finalize(ctxt.1)?;
        if let Some(token) = ctxt.0 {
            Ok(Self { token, inner })
        } else {
            Err(Error::validation("csrf_token is required").into())
        }
    }
}

#[async_trait]
impl<'r, T: FromForm<'r>> FromData<'r> for CsrfForm<T> {
    type Error = CsrfError<<Form<T> as FromData<'r>>::Error>;
    async fn from_data(r: &'r Request<'_>, d: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        let token: CsrfToken = match r.guard().await {
            Success(t) => t,
            Failure((s, _e)) => return Outcome::Failure((s, CsrfError::CSRFTokenInvalid)),
            Forward(()) => return Outcome::Forward(d),
        };
        let form: Form<CsrfTokenForm<T>> = match Form::from_data(r, d).await {
            Success(t) => t,
            Failure((s, e)) => return Outcome::Failure((s, CsrfError::Other(e))),
            Forward(d) => return Outcome::Forward(d),
        };
        if token.verify(form.token).is_ok() {
            Outcome::Success(Self(form.into_inner().inner))
        } else {
            Outcome::Failure((Status::NotAcceptable, CsrfError::CSRFTokenInvalid))
        }
    }
}
