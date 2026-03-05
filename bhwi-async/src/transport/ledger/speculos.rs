use std::fmt::{Debug, Display};

use async_trait::async_trait;
use hex::FromHexError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::Transport;

pub struct SpeculosTransport<C> {
    pub client: C,
}

impl<C> SpeculosTransport<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

#[derive(Serialize, Deserialize)]
/// Apdu response from speculos emulator
pub struct Apdu {
    /// hex encoded apdu data
    data: String,
}

#[async_trait(?Send)]
pub trait SpeculosClient {
    type Error: Debug + From<FromHexError>;

    /// The endpoint that the speculos emulator is listening on.
    /// Ex. "localhost:5000"
    fn url(&self) -> &str;

    async fn post<Req: Serialize>(&self, endpoint: &str, json_req: Req) -> Result<(), Self::Error>;

    async fn post_json<Req: Serialize, Res: DeserializeOwned>(
        &self,
        endpoint: &str,
        json_req: Req,
    ) -> Result<Res, Self::Error>;

    async fn button_press(&self, button: Button) -> Result<(), Self::Error> {
        Self::post(
            self,
            &format!("{}/button/{button}", Self::url(self)),
            &ButtonRequest {
                action: "press-and-release".into(),
            },
        )
        .await
    }

    async fn set_automation<T: Serialize>(&self, automation_json: &T) -> Result<(), Self::Error> {
        Self::post(
            self,
            &format!("{}/automation", Self::url(self)),
            automation_json,
        )
        .await
    }
}

#[async_trait(?Send)]
impl<C: SpeculosClient> Transport for SpeculosTransport<C> {
    type Error = <C as SpeculosClient>::Error;

    async fn exchange(
        &mut self,
        apdu_command: &[u8],
        _encrypted: bool,
    ) -> Result<Vec<u8>, Self::Error> {
        let Apdu { data } = self
            .client
            .post_json(
                &format!("{}/apdu", self.client.url()),
                &Apdu {
                    data: hex::encode(apdu_command),
                },
            )
            .await?;
        Ok(hex::decode(data)?)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Button {
    Left,
    Right,
    Both,
}

impl Display for Button {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Button::Left => "left",
                Button::Right => "right",
                Button::Both => "both",
            }
        )
    }
}

#[derive(Serialize)]
struct ButtonRequest {
    action: String,
}
