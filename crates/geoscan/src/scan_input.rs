use std::io::{self, IsTerminal, Write};

use console::{Term, style};
use geoscan_core::detect::normalize_target;

const DEFAULT_TARGET: &str = "http://127.0.0.1:8080/geoserver";

pub struct ScanInput {
    pub target: String,
    credentials: Option<Credentials>,
}

// Keep passwords out of debug output and persistent configuration.
struct Credentials {
    username: String,
    password: String,
}

impl ScanInput {
    pub fn auth(&self) -> Option<(&str, &str)> {
        self.credentials
            .as_ref()
            .map(|credentials| (credentials.username.as_str(), credentials.password.as_str()))
    }
}

trait Prompter {
    fn target(&mut self) -> Result<String, String>;
    fn username(&mut self) -> Result<String, String>;
    fn password(&mut self) -> Result<String, String>;
    fn invalid_target(&mut self, error: &str);
}

struct TerminalPrompter;

impl TerminalPrompter {
    fn read_line(prompt: &str) -> Result<String, String> {
        eprint!("{prompt}");
        io::stderr().flush().map_err(|error| error.to_string())?;
        let mut line = String::new();
        if io::stdin()
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err("Input closed; scan cancelled".into());
        }
        Ok(line.trim().to_owned())
    }
}

impl Prompter for TerminalPrompter {
    fn target(&mut self) -> Result<String, String> {
        Self::read_line(&format!("[1/3] Target URL [{DEFAULT_TARGET}]: "))
    }

    fn username(&mut self) -> Result<String, String> {
        Self::read_line("[2/3] Username (Enter to skip login): ")
    }

    fn password(&mut self) -> Result<String, String> {
        let terminal = Term::stderr();
        terminal
            .write_str("[3/3] Password (hidden): ")
            .map_err(|error| error.to_string())?;
        terminal
            .read_secure_line()
            .map_err(|_| "Could not read password from the terminal".to_owned())
    }

    fn invalid_target(&mut self, error: &str) {
        eprintln!("  Invalid target: {error}. Try again.");
    }
}

pub fn collect_scan_input(
    target: Option<String>,
    username: Option<String>,
    no_input: bool,
) -> Result<ScanInput, String> {
    let interactive = !no_input && io::stdin().is_terminal() && io::stderr().is_terminal();
    let environment_password = match std::env::var("GEOSCAN_PASSWORD") {
        Ok(password) => Some(password),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("GEOSCAN_PASSWORD must contain valid UTF-8".into());
        }
    };

    if interactive {
        eprintln!("\n{}", style("GeoScan | Scan setup").bold().cyan());
        eprintln!("Enter your server details. Login is optional.\n");
    }

    resolve_scan_input(
        target,
        username,
        environment_password,
        interactive,
        &mut TerminalPrompter,
    )
}

fn resolve_scan_input(
    target: Option<String>,
    username: Option<String>,
    environment_password: Option<String>,
    interactive: bool,
    prompter: &mut impl Prompter,
) -> Result<ScanInput, String> {
    let target = if let Some(target) = target {
        normalize_target(&target)?.to_string()
    } else if interactive {
        loop {
            let answer = prompter.target()?;
            let value = if answer.trim().is_empty() {
                DEFAULT_TARGET
            } else {
                answer.trim()
            };
            match normalize_target(value) {
                Ok(target) => break target.to_string(),
                Err(error) => prompter.invalid_target(&error),
            }
        }
    } else {
        return Err("Supply --target URL, or run geoscan scan in a terminal for prompts".into());
    };

    let username = if let Some(username) = username {
        let username = username.trim().to_owned();
        if username.is_empty() {
            return Err("Username cannot be blank; omit --username to skip login".into());
        }
        Some(username)
    } else if interactive {
        let username = prompter.username()?.trim().to_owned();
        (!username.is_empty()).then_some(username)
    } else {
        None
    };

    let credentials = if let Some(username) = username {
        if username.contains(':') || username.chars().any(char::is_control) {
            return Err("Username cannot contain colons or control characters".into());
        }
        let password = match environment_password.filter(|value| !value.is_empty()) {
            Some(password) => password,
            None if interactive => prompter.password()?,
            None => {
                return Err("Set GEOSCAN_PASSWORD when using --username without prompts".into());
            }
        };
        if password.is_empty() {
            return Err("Password cannot be blank; scan cancelled".into());
        }
        Some(Credentials { username, password })
    } else {
        None
    };

    Ok(ScanInput {
        target,
        credentials,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Default)]
    struct FakePrompter {
        targets: VecDeque<String>,
        username: String,
        password: String,
        target_reads: usize,
        username_reads: usize,
        password_reads: usize,
        invalid_targets: usize,
    }

    impl Prompter for FakePrompter {
        fn target(&mut self) -> Result<String, String> {
            self.target_reads += 1;
            self.targets.pop_front().ok_or("Input closed".into())
        }

        fn username(&mut self) -> Result<String, String> {
            self.username_reads += 1;
            Ok(self.username.clone())
        }

        fn password(&mut self) -> Result<String, String> {
            self.password_reads += 1;
            Ok(self.password.clone())
        }

        fn invalid_target(&mut self, _: &str) {
            self.invalid_targets += 1;
        }
    }

    #[test]
    fn blank_answers_use_docker_target_and_skip_login() {
        let mut prompts = FakePrompter {
            targets: VecDeque::from([String::new()]),
            ..Default::default()
        };
        let input = resolve_scan_input(None, None, None, true, &mut prompts).unwrap();
        assert_eq!(input.target, format!("{DEFAULT_TARGET}/"));
        assert!(input.auth().is_none());
        assert_eq!(prompts.password_reads, 0);
    }

    #[test]
    fn prompts_retry_invalid_urls_and_preserve_password_spaces() {
        let mut prompts = FakePrompter {
            targets: VecDeque::from(["bad url".into(), "https://example.org/maps".into()]),
            username: " admin ".into(),
            password: " password with spaces ".into(),
            ..Default::default()
        };
        let input = resolve_scan_input(None, None, None, true, &mut prompts).unwrap();
        assert_eq!(input.target, "https://example.org/maps/");
        assert_eq!(input.auth(), Some(("admin", " password with spaces ")));
        assert_eq!(prompts.invalid_targets, 1);
        assert_eq!(prompts.password_reads, 1);
    }

    #[test]
    fn supplied_fields_are_not_prompted_and_environment_supplies_the_password() {
        let mut prompts = FakePrompter::default();
        let input = resolve_scan_input(
            Some(DEFAULT_TARGET.into()),
            Some("admin".into()),
            Some("test-password".into()),
            true,
            &mut prompts,
        )
        .unwrap();
        assert_eq!(input.auth(), Some(("admin", "test-password")));
        assert_eq!(prompts.target_reads, 0);
        assert_eq!(prompts.username_reads, 0);
        assert_eq!(prompts.password_reads, 0);
    }

    #[test]
    fn supplied_username_can_prompt_for_just_the_password() {
        let mut prompts = FakePrompter {
            password: "test-password".into(),
            ..Default::default()
        };
        let input = resolve_scan_input(
            Some(DEFAULT_TARGET.into()),
            Some("admin".into()),
            None,
            true,
            &mut prompts,
        )
        .unwrap();
        assert!(input.auth().is_some());
        assert_eq!(prompts.password_reads, 1);
        assert_eq!(prompts.username_reads, 0);
    }

    #[test]
    fn noninteractive_input_requires_target_and_a_password_for_login() {
        let mut prompts = FakePrompter::default();
        assert!(
            resolve_scan_input(None, None, None, false, &mut prompts)
                .err()
                .unwrap()
                .contains("--target")
        );
        assert!(
            resolve_scan_input(
                Some(DEFAULT_TARGET.into()),
                Some("admin".into()),
                None,
                false,
                &mut prompts,
            )
            .err()
            .unwrap()
            .contains("GEOSCAN_PASSWORD")
        );
        assert_eq!(prompts.target_reads + prompts.password_reads, 0);
    }

    #[test]
    fn rejects_invalid_credentials_and_does_not_use_a_password_without_a_username() {
        for username in ["", "admin:other", "admin\nother"] {
            let error = resolve_scan_input(
                Some(DEFAULT_TARGET.into()),
                Some(username.into()),
                Some("test-password".into()),
                false,
                &mut FakePrompter::default(),
            )
            .err()
            .unwrap();
            assert!(error.contains("Username"));
            assert!(!error.contains("test-password"));
        }
        let input = resolve_scan_input(
            Some(DEFAULT_TARGET.into()),
            None,
            Some("test-password".into()),
            false,
            &mut FakePrompter::default(),
        )
        .unwrap();
        assert!(input.auth().is_none());
    }
}
