# BHWI, the Bitcoin Hardware Wallet Interface

This repository is a work in progress for a sans-io equivalent of HWI.
The main idea is to implement for each hardware wallet an interface called
the interpreter that takes care of encoding commands, decoding device responses
and routing data to their recipients.

```rust
pub trait Interpreter {
    type Command;
    type Transmit;
    type Response;
    type Error;
    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error>;
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error>;
    fn end(self) -> Result<Self::Response, Self::Error>;
}
```

Once this trait implemented, it is up to the developer to take care of the IO according to the
targeted platform with or without `async/await`. The data and its
recipient are provided in the `Transmit` structure.

For example the code of `bhwi-async` to run a command from the common interpreter that currently
manage commands for coldcard, ledger and jade devices and the jade pin server:

```rust
pub trait Device<C, T, R, E> {
    type TransportError: Debug;
    type HttpClientError: Debug;
    fn components(
        &mut self,
    ) -> (
        &mut dyn Transport<Error = Self::TransportError>,
        &dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    );
}

async fn run_command<'a, D, C, E, F>(
    device: &'a mut D,
    command: C,
) -> Result<common::Response, Error<E, F>>
where
    E: std::fmt::Debug + 'a,
    F: std::fmt::Debug + 'a,
    D: Device<
        common::Command,
        common::Transmit,
        common::Response,
        common::Error,
        TransportError = E,
        HttpClientError = F,
    >,
    C: Into<common::Command>,
{
    let (transport, http_client, mut intpr) = device.components();
    let transmit = intpr.start(command.into())?;
    let exchange = transport
        .exchange(&transmit.payload, transmit.encrypted)
        .await
        .map_err(Error::Transport)?;
    let mut transmit = intpr.exchange(exchange)?;
    while let Some(t) = &transmit {
        match &t.recipient {
            common::Recipient::PinServer { url } => {
                let res = http_client
                    .request(url, &t.payload)
                    .await
                    .map_err(Error::HttpClient)?;
                transmit = intpr.exchange(res)?;
            }
            common::Recipient::Device => {
                let exchange = transport
                    .exchange(&t.payload, t.encrypted)
                    .await
                    .map_err(Error::Transport)?;
                transmit = intpr.exchange(exchange)?;
            }
        }
    }
    intpr.end().map_err(|e| e.into())
}

```
