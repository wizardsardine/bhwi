# BHWI, the Bitcoin Hardware Wallet Interface

This repository is a work in progress for a sans-io equivalent of HWI.
The main idea is to implement for each hardware wallet a interface called
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
targeted plateform with or without `async/await`. The data and its
recipient are provided in the `Transmit` structure.

For example the code of `bhwi-async` to run a command from the common interpreter that currently
manage commands for ledger and jade devices and the jade pin server:

```rust
async fn run_command<T, S, I>(
    transport: &T,
    http_client: &S,
    mut intpr: I,
    command: common::Command,
) -> Result<common::Response, Error<T::Error, S::Error>>
where
    T: Transport + ?Sized,
    S: HttpClient + ?Sized,
    I: Interpreter<
        Command = common::Command,
        Transmit = common::Transmit,
        Response = common::Response,
        Error = common::Error,
    >,
{
    let transmit = intpr.start(command)?;
    let exchange = transport
        .exchange(&transmit.payload)
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
                    .exchange(&t.payload)
                    .await
                    .map_err(Error::Transport)?;
                transmit = intpr.exchange(exchange)?;
            }
        }
    }
    intpr.end().map_err(|e| e.into())
}

```
