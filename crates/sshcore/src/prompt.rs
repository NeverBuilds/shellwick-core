//! Keyboard-interactive sign-in: servers that ask questions while signing in
//! (a two-factor "Verification code:", "Password:" through PAM, a bastion's
//! own prompts).
//!
//! Rules (decided with the owner):
//! - A question that looks like the account password (hidden input, mentions
//!   "password") is answered once with the saved password, if there is one.
//!   Everything else is asked, through the caller's [`Ask`] hook (the UI shows
//!   a banner in the tab). If the server asks the same password question
//!   again, the saved one was wrong: the user is asked instead.
//! - Codes are never stored; answers never leave this exchange (no logs).
//! - A cancelled question, or a server that stopped waiting, ends the attempt
//!   without retrying (automatic reconnects would otherwise spam prompts or
//!   lock the account).

use crate::{Error, HostConfig, TofuHandler};
use russh::client::{Handle, KeyboardInteractiveAuthResponse};
use serde::Serialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// One question from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Question {
    pub text: String,
    /// Show what is typed (codes, user names); false = hide it (passwords, PINs).
    pub echo: bool,
}

/// What to show the user: which server asks, its texts, and the questions
/// Shellwick couldn't answer by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Challenge {
    /// The server asking: the tab's host or its jump host.
    pub host_id: String,
    pub host_name: String,
    /// The server's title for this step (often empty).
    pub name: String,
    /// The server's instructions (often empty).
    pub instructions: String,
    pub questions: Vec<Question>,
    /// The same questions came back after an answer: the last one was refused.
    pub retry: bool,
}

pub type AskFuture = Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send>>;

/// Asks the user a [`Challenge`]; `None` means cancelled. One answer per question.
pub type Ask = Arc<dyn Fn(Challenge) -> AskFuture + Send + Sync>;

/// For callers without a UI: every question is cancelled at once.
pub fn never_ask() -> Ask {
    Arc::new(|_| Box::pin(async { None }))
}

/// Does this look like the account password question (not a code, PIN or a
/// new-password dialogue)?
pub fn is_password_question(q: &Question) -> bool {
    let t = q.text.to_lowercase();
    !q.echo
        && t.contains("password")
        && !["new", "again", "retype", "re-enter", "confirm", "code", "token", "otp", "pin", "verification", "passcode", "one-time"]
            .iter()
            .any(|w| t.contains(w))
}

/// What Shellwick can answer by itself: the saved password for the password
/// question, once per sign-in. `None` entries are asked.
pub fn plan(questions: &[Question], saved_password: Option<&str>, password_used: bool) -> Vec<Option<String>> {
    let mut used = password_used;
    questions
        .iter()
        .map(|q| match saved_password {
            Some(pw) if !used && is_password_question(q) => {
                used = true;
                Some(pw.to_string())
            }
            _ => None,
        })
        .collect()
}

// --- The exchange -----------------------------------------------------------------

/// One step of the server's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    Success,
    Failure,
    Questions { name: String, instructions: String, questions: Vec<Question> },
}

/// The client side of a keyboard-interactive exchange: russh's handle, or a
/// scripted fake in tests.
pub(crate) trait Exchange: Send {
    fn start(&mut self, user: &str) -> impl Future<Output = Result<Step, Error>> + Send;
    fn respond(&mut self, answers: Vec<String>) -> impl Future<Output = Result<Step, Error>> + Send;
}

fn step(r: KeyboardInteractiveAuthResponse) -> Step {
    match r {
        KeyboardInteractiveAuthResponse::Success => Step::Success,
        KeyboardInteractiveAuthResponse::Failure { .. } => Step::Failure,
        KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => Step::Questions {
            name,
            instructions,
            questions: prompts.into_iter().map(|p| Question { text: p.prompt, echo: p.echo }).collect(),
        },
    }
}

impl Exchange for Handle<TofuHandler> {
    async fn start(&mut self, user: &str) -> Result<Step, Error> {
        Ok(step(self.authenticate_keyboard_interactive_start(user, None).await?))
    }
    async fn respond(&mut self, answers: Vec<String>) -> Result<Step, Error> {
        Ok(step(self.authenticate_keyboard_interactive_respond(answers).await?))
    }
}

/// How an exchange ended (errors aside).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    SignedIn,
    /// The server turned keyboard-interactive down before asking anything.
    Refused,
}

/// Rounds of questions before giving up (servers normally need one or two).
const MAX_ROUNDS: usize = 20;

/// Runs the exchange for `cfg`. `after_partial`: another method was already
/// accepted (e.g. the key) and this is the second factor.
pub(crate) async fn run<E: Exchange>(ex: &mut E, cfg: &HostConfig, saved_password: Option<&str>, ask: &Ask, after_partial: bool) -> Result<Outcome, Error> {
    let mut next = ex.start(&cfg.user).await?;
    let mut password_used = false;
    let mut asked_before: Option<Vec<Question>> = None;
    let mut answered_anything = false;
    for _ in 0..MAX_ROUNDS {
        let (name, instructions, questions) = match next {
            Step::Success => return Ok(Outcome::SignedIn),
            Step::Failure if !answered_anything => return Ok(Outcome::Refused),
            Step::Failure => return Err(Error::AuthFailed("the server didn't accept the answers".into())),
            Step::Questions { name, instructions, questions } => (name, instructions, questions),
        };
        // Servers may send an empty round (just text, or nothing): acknowledge it.
        if questions.is_empty() {
            next = ex.respond(Vec::new()).await?;
            continue;
        }
        let mut answers = plan(&questions, saved_password, password_used);
        password_used |= answers.iter().any(Option::is_some);
        let missing: Vec<usize> = (0..questions.len()).filter(|&i| answers[i].is_none()).collect();
        let mut asked_user = false;
        if !missing.is_empty() {
            let asked: Vec<Question> = missing.iter().map(|&i| questions[i].clone()).collect();
            let challenge = Challenge {
                host_id: cfg.id.clone(),
                host_name: cfg.name.clone(),
                name,
                instructions,
                retry: asked_before.as_ref() == Some(&asked),
                questions: asked.clone(),
            };
            let Some(given) = ask(challenge).await else { return Err(Error::AuthCancelled { partial: after_partial }) };
            if given.len() != missing.len() {
                return Err(Error::AuthCancelled { partial: after_partial });
            }
            for (i, a) in missing.iter().zip(given) {
                answers[*i] = Some(a);
            }
            asked_before = Some(asked);
            asked_user = true;
        }
        answered_anything = true;
        let answers: Vec<String> = answers.into_iter().map(Option::unwrap_or_default).collect();
        next = match ex.respond(answers).await {
            Ok(s) => s,
            // The user took longer than the server was willing to wait.
            Err(_) if asked_user => return Err(Error::AuthPromptExpired),
            Err(e) => return Err(e),
        };
    }
    Err(Error::AuthFailed("the server kept asking questions".into()))
}

// --- Sessions: a question waits for the handle's answer ---------------------------

/// Hands the user's answers (or `None` = cancel) to the waiting question.
type Reply = oneshot::Sender<Option<Vec<String>>>;

/// Where a session's pending question waits for its answer.
#[derive(Clone, Default)]
pub(crate) struct PromptSlot(Arc<Mutex<Option<Reply>>>);

/// Reports a challenge to whoever will answer it (e.g. sends a session event).
pub(crate) type NotifyFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

impl PromptSlot {
    /// An [`Ask`] that reports each challenge with `notify` and waits for [`PromptSlot::answer`].
    pub fn ask(&self, notify: impl Fn(Challenge) -> NotifyFuture + Send + Sync + 'static) -> Ask {
        let slot = self.clone();
        let notify = Arc::new(notify);
        Arc::new(move |challenge| {
            let slot = slot.clone();
            let notify = notify.clone();
            Box::pin(async move {
                let (tx, rx) = oneshot::channel();
                *slot.0.lock().unwrap() = Some(tx);
                notify(challenge).await;
                rx.await.ok().flatten()
            })
        })
    }

    /// Delivers the user's answers (`None` = cancel). False when nothing was waiting.
    pub fn answer(&self, answers: Option<Vec<String>>) -> bool {
        match self.0.lock().unwrap().take() {
            Some(tx) => tx.send(answers).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthMethod;
    use std::collections::VecDeque;

    fn q(text: &str, echo: bool) -> Question {
        Question { text: text.into(), echo }
    }

    fn host() -> HostConfig {
        HostConfig {
            id: "h1".into(),
            name: "bastion".into(),
            host: "h".into(),
            port: 22,
            user: "deploy".into(),
            auth: AuthMethod::Password,
            host_key_fingerprint: None,
            startup_command: None,
            tags: vec![],
            environment: None,
            folder: None,
            forwards: vec![],
            jump_host: None,
            confirm_new_key: false,
            session_log: false,
            terminal_theme: None,
            proxy: None,
            forward_agent: false,
            keepalive_secs: None,
            legacy_algorithms: false,
        }
    }

    /// A scripted server: answers each call with the next step, records what it got.
    struct Script {
        steps: VecDeque<Result<Step, Error>>,
        got: Vec<Vec<String>>,
    }

    impl Script {
        fn new(steps: Vec<Result<Step, Error>>) -> Self {
            Self { steps: steps.into(), got: Vec::new() }
        }
    }

    impl Exchange for Script {
        async fn start(&mut self, _: &str) -> Result<Step, Error> {
            self.steps.pop_front().expect("no more steps")
        }
        async fn respond(&mut self, answers: Vec<String>) -> Result<Step, Error> {
            self.got.push(answers);
            self.steps.pop_front().expect("no more steps")
        }
    }

    fn questions(qs: &[(&str, bool)]) -> Result<Step, Error> {
        Ok(Step::Questions { name: String::new(), instructions: String::new(), questions: qs.iter().map(|(t, e)| q(t, *e)).collect() })
    }

    /// Answers with fixed values and records the challenges it saw.
    fn answering(values: Vec<Option<Vec<&'static str>>>) -> (Ask, Arc<Mutex<Vec<Challenge>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(values)));
        let s = seen.clone();
        let ask: Ask = Arc::new(move |c| {
            s.lock().unwrap().push(c);
            let next = queue.lock().unwrap().pop_front().flatten();
            Box::pin(async move { next.map(|v| v.into_iter().map(String::from).collect()) })
        });
        (ask, seen)
    }

    #[test]
    fn password_questions_are_recognised() {
        assert!(is_password_question(&q("Password: ", false)));
        assert!(is_password_question(&q("deploy@host's password:", false)));
        assert!(!is_password_question(&q("Password: ", true)), "shown input isn't a password field");
        assert!(!is_password_question(&q("Verification code: ", false)));
        assert!(!is_password_question(&q("New password: ", false)));
        assert!(!is_password_question(&q("Retype new password: ", false)));
        assert!(!is_password_question(&q("Password + OTP token:", false)));
        assert!(!is_password_question(&q("Enter PIN for YubiKey:", false)));
    }

    #[test]
    fn saved_password_answers_once() {
        let qs = [q("Password:", false), q("Verification code:", true)];
        assert_eq!(plan(&qs, Some("pw"), false), [Some("pw".into()), None]);
        assert_eq!(plan(&qs, Some("pw"), true), [None, None], "already used: ask");
        assert_eq!(plan(&qs, None, false), [None, None]);
        let twice = [q("Password:", false), q("Password:", false)];
        assert_eq!(plan(&twice, Some("pw"), false), [Some("pw".into()), None]);
    }

    #[tokio::test]
    async fn password_then_code() {
        let mut s = Script::new(vec![questions(&[("Password:", false)]), questions(&[("Verification code:", true)]), Ok(Step::Success)]);
        let (ask, seen) = answering(vec![Some(vec!["123456"])]);
        assert_eq!(run(&mut s, &host(), Some("pw"), &ask, false).await.unwrap(), Outcome::SignedIn);
        assert_eq!(s.got, [vec!["pw".to_string()], vec!["123456".to_string()]]);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "only the code was asked");
        assert_eq!((seen[0].host_id.as_str(), seen[0].host_name.as_str(), seen[0].retry), ("h1", "bastion", false));
        assert_eq!(seen[0].questions, [q("Verification code:", true)]);
    }

    #[tokio::test]
    async fn mixed_round_asks_only_what_it_cannot_answer() {
        let mut s = Script::new(vec![questions(&[("Password:", false), ("OTP:", true)]), Ok(Step::Success)]);
        let (ask, seen) = answering(vec![Some(vec!["987654"])]);
        run(&mut s, &host(), Some("pw"), &ask, false).await.unwrap();
        assert_eq!(s.got, [vec!["pw".to_string(), "987654".to_string()]]);
        assert_eq!(seen.lock().unwrap()[0].questions.len(), 1);
    }

    #[tokio::test]
    async fn wrong_saved_password_then_ask() {
        // The server asks for the password again: the saved one was wrong.
        let mut s = Script::new(vec![questions(&[("Password:", false)]), questions(&[("Password:", false)]), Ok(Step::Success)]);
        let (ask, seen) = answering(vec![Some(vec!["typed"])]);
        run(&mut s, &host(), Some("old"), &ask, false).await.unwrap();
        assert_eq!(s.got, [vec!["old".to_string()], vec!["typed".to_string()]]);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refused_code_is_marked_as_retry() {
        let mut s = Script::new(vec![questions(&[("Code:", true)]), questions(&[("Code:", true)]), Ok(Step::Success)]);
        let (ask, seen) = answering(vec![Some(vec!["111111"]), Some(vec!["222222"])]);
        run(&mut s, &host(), None, &ask, true).await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!((seen[0].retry, seen[1].retry), (false, true));
    }

    #[tokio::test]
    async fn empty_rounds_are_acknowledged() {
        let mut s = Script::new(vec![questions(&[]), questions(&[("Code:", true)]), Ok(Step::Success)]);
        let (ask, _) = answering(vec![Some(vec!["1"])]);
        run(&mut s, &host(), None, &ask, false).await.unwrap();
        assert_eq!(s.got, [Vec::<String>::new(), vec!["1".to_string()]]);
    }

    #[tokio::test]
    async fn cancel_expiry_refusal_and_failure() {
        // Cancelled by the user.
        let mut s = Script::new(vec![questions(&[("Code:", true)])]);
        let (ask, _) = answering(vec![None]);
        assert!(matches!(run(&mut s, &host(), None, &ask, true).await, Err(Error::AuthCancelled { partial: true })));
        // The server stopped waiting while the user typed.
        let mut s = Script::new(vec![questions(&[("Code:", true)]), Err(Error::Closed)]);
        let (ask, _) = answering(vec![Some(vec!["1"])]);
        assert!(matches!(run(&mut s, &host(), None, &ask, false).await, Err(Error::AuthPromptExpired)));
        // Keyboard-interactive turned down straight away.
        let mut s = Script::new(vec![Ok(Step::Failure)]);
        assert_eq!(run(&mut s, &host(), None, &never_ask(), false).await.unwrap(), Outcome::Refused);
        // Wrong answer, final.
        let mut s = Script::new(vec![questions(&[("Code:", true)]), Ok(Step::Failure)]);
        let (ask, _) = answering(vec![Some(vec!["0"])]);
        assert!(matches!(run(&mut s, &host(), None, &ask, false).await, Err(Error::AuthFailed(_))));
        // Wrong number of answers counts as cancelled.
        let mut s = Script::new(vec![questions(&[("A:", true), ("B:", true)])]);
        let (ask, _) = answering(vec![Some(vec!["only one"])]);
        assert!(matches!(run(&mut s, &host(), None, &ask, false).await, Err(Error::AuthCancelled { partial: false })));
    }

    #[tokio::test]
    async fn slot_delivers_answers() {
        let slot = PromptSlot::default();
        let seen = Arc::new(Mutex::new(None));
        let s2 = seen.clone();
        let ask = slot.ask(move |c| {
            *s2.lock().unwrap() = Some(c);
            Box::pin(async {})
        });
        assert!(!slot.answer(Some(vec![])), "nothing waiting yet");
        let waiting = tokio::spawn(ask(Challenge {
            host_id: "h".into(),
            host_name: "n".into(),
            name: String::new(),
            instructions: String::new(),
            questions: vec![q("Code:", true)],
            retry: false,
        }));
        while seen.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
        assert!(slot.answer(Some(vec!["42".into()])));
        assert_eq!(waiting.await.unwrap(), Some(vec!["42".to_string()]));
    }
}
