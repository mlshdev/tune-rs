use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Running,
    Stopped,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("service is unavailable")]
    Unavailable,
    #[error("service did not acknowledge the request in time")]
    Timeout,
}

#[derive(Clone)]
pub struct Controller {
    commands: mpsc::Sender<Command>,
    state: watch::Receiver<State>,
}

pub struct Worker {
    commands: mpsc::Receiver<Command>,
    state: watch::Sender<State>,
}

pub struct Command {
    pub state: State,
    pub restart: bool,
    response: oneshot::Sender<()>,
}

pub fn channel() -> (Controller, Worker) {
    let (commands, receiver) = mpsc::channel(8);
    let (state, status) = watch::channel(State::Stopped);
    (
        Controller {
            commands,
            state: status,
        },
        Worker {
            commands: receiver,
            state,
        },
    )
}

impl Controller {
    pub fn state(&self) -> State {
        *self.state.borrow()
    }

    pub async fn apply(&self, state: State, restart: bool) -> Result<(), Error> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (response, receiver) = oneshot::channel();
            self.commands
                .send(Command {
                    state,
                    restart,
                    response,
                })
                .await
                .map_err(|_| Error::Unavailable)?;
            receiver.await.map_err(|_| Error::Unavailable)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

impl Worker {
    pub async fn next(&mut self) -> Option<Command> {
        self.commands.recv().await
    }

    pub fn publish(&self, state: State) {
        self.state.send_replace(state);
    }
}

impl Command {
    pub fn acknowledge(self) {
        let _ = self.response.send(());
    }
}
