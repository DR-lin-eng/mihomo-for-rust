use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Run,
    ConvertRuleset(Vec<String>),
    Generate(Vec<String>),
}

impl Default for Command {
    fn default() -> Self {
        Self::Run
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootOptions {
    pub home_dir: Option<String>,
    pub config_file: Option<String>,
    pub config_base64: Option<String>,
    pub external_ui: Option<String>,
    pub external_controller: Option<String>,
    pub external_controller_unix: Option<String>,
    pub external_controller_pipe: Option<String>,
    pub secret: Option<String>,
    pub post_up: Option<String>,
    pub post_down: Option<String>,
    pub geodata_mode: bool,
    pub show_version: bool,
    pub test_config: bool,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    HelpRequested,
    MissingValue(&'static str),
    UnexpectedPositional(String),
    UnknownFlag(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested => write!(f, "help requested"),
            Self::MissingValue(flag) => write!(f, "missing value for flag {flag}"),
            Self::UnexpectedPositional(value) => {
                write!(f, "unexpected positional argument: {value}")
            }
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigSource {
    File(PathBuf),
    Stdin,
    Base64(String),
}

impl ConfigSource {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Stdin => "stdin",
            Self::Base64(_) => "base64",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedBoot {
    pub home_dir: PathBuf,
    pub config_source: ConfigSource,
    pub command: Command,
    pub geodata_mode: bool,
    pub show_version: bool,
    pub test_config: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootEnvironment {
    pub user_home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
}

impl BootEnvironment {
    pub fn from_process() -> Self {
        Self {
            user_home: std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        }
    }
}

pub fn parse_args<I, S>(args: I) -> Result<BootOptions, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();

    let mut options = BootOptions::default();
    let mut pending = iter.next();

    if let Some(command) = pending.clone() {
        match command.as_str() {
            "convert-ruleset" => {
                options.command = Command::ConvertRuleset(iter.collect());
                return Ok(options);
            }
            "generate" => {
                options.command = Command::Generate(iter.collect());
                return Ok(options);
            }
            _ => {}
        }
    }

    while let Some(arg) = pending.take().or_else(|| iter.next()) {
        if arg == "--" {
            break;
        }
        let raw_flag = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .ok_or_else(|| ParseError::UnexpectedPositional(arg.clone()))?;
        let (flag, inline) = raw_flag
            .split_once('=')
            .map_or((raw_flag, None), |(flag, value)| (flag, Some(value)));
        let mut value = |name| {
            inline
                .map(str::to_owned)
                .map(Ok)
                .unwrap_or_else(|| next_value(name, &mut iter))
        };
        match flag {
            "h" | "help" => return Err(ParseError::HelpRequested),
            "d" => options.home_dir = Some(value("-d")?),
            "f" => options.config_file = Some(value("-f")?),
            "config" => options.config_base64 = Some(value("-config")?),
            "ext-ui" => options.external_ui = Some(value("-ext-ui")?),
            "ext-ctl" => options.external_controller = Some(value("-ext-ctl")?),
            "ext-ctl-unix" => options.external_controller_unix = Some(value("-ext-ctl-unix")?),
            "ext-ctl-pipe" => options.external_controller_pipe = Some(value("-ext-ctl-pipe")?),
            "secret" => options.secret = Some(value("-secret")?),
            "post-up" => options.post_up = Some(value("-post-up")?),
            "post-down" => options.post_down = Some(value("-post-down")?),
            "m" | "v" | "t" => {
                let enabled = match inline {
                    None | Some("true" | "1" | "t" | "T" | "TRUE" | "True") => true,
                    Some("false" | "0" | "f" | "F" | "FALSE" | "False") => false,
                    _ => return Err(ParseError::UnknownFlag(arg)),
                };
                match flag {
                    "m" => options.geodata_mode = enabled,
                    "v" => options.show_version = enabled,
                    _ => options.test_config = enabled,
                }
            }
            _ => return Err(ParseError::UnknownFlag(arg)),
        }
    }

    Ok(options)
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::ConvertRuleset(_) => "convert-ruleset",
            Self::Generate(_) => "generate",
        }
    }
}

impl ResolvedBoot {
    pub fn config_display_path(&self) -> PathBuf {
        match &self.config_source {
            ConfigSource::File(path) => path.clone(),
            ConfigSource::Base64(_) | ConfigSource::Stdin => self.home_dir.join("config.yaml"),
        }
    }
}

impl BootOptions {
    pub fn with_process_environment(mut self) -> Self {
        let get = |name| std::env::var(name).ok().filter(|value| !value.is_empty());
        for (slot, name) in [
            (&mut self.home_dir, "CLASH_HOME_DIR"),
            (&mut self.config_file, "CLASH_CONFIG_FILE"),
            (&mut self.config_base64, "CLASH_CONFIG_STRING"),
            (&mut self.external_ui, "CLASH_OVERRIDE_EXTERNAL_UI_DIR"),
            (
                &mut self.external_controller,
                "CLASH_OVERRIDE_EXTERNAL_CONTROLLER",
            ),
            (
                &mut self.external_controller_unix,
                "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX",
            ),
            (
                &mut self.external_controller_pipe,
                "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE",
            ),
            (&mut self.secret, "CLASH_OVERRIDE_SECRET"),
            (&mut self.post_up, "CLASH_POST_UP"),
            (&mut self.post_down, "CLASH_POST_DOWN"),
        ] {
            if slot.is_none() {
                *slot = get(name);
            }
        }
        self
    }

    pub fn resolve(&self, cwd: &Path, env: &BootEnvironment) -> ResolvedBoot {
        let provisional_home_dir = resolve_home_dir(
            self.home_dir.as_deref(),
            cwd,
            env,
            &ConfigSource::File(PathBuf::new()),
        );
        let config_source = resolve_config_source(self, cwd, &provisional_home_dir);
        let home_dir = resolve_home_dir(self.home_dir.as_deref(), cwd, env, &config_source);
        ResolvedBoot {
            home_dir,
            config_source,
            command: self.command.clone(),
            geodata_mode: self.geodata_mode,
            show_version: self.show_version,
            test_config: self.test_config,
        }
    }
}

fn next_value<I>(flag: &'static str, iter: &mut I) -> Result<String, ParseError>
where
    I: Iterator<Item = String>,
{
    iter.next().ok_or(ParseError::MissingValue(flag))
}

fn resolve_home_dir(
    home_dir: Option<&str>,
    cwd: &Path,
    env: &BootEnvironment,
    config_source: &ConfigSource,
) -> PathBuf {
    match home_dir {
        Some(path) => resolve_cwd_relative(cwd, path),
        None => default_home_dir(cwd, env, config_source),
    }
}

fn resolve_config_source(options: &BootOptions, cwd: &Path, home_dir: &Path) -> ConfigSource {
    if let Some(config_base64) = &options.config_base64 {
        return ConfigSource::Base64(config_base64.clone());
    }

    match options.config_file.as_deref() {
        Some("-") => ConfigSource::Stdin,
        Some(path) => ConfigSource::File(resolve_cwd_relative(cwd, path)),
        None => ConfigSource::File(home_dir.join("config.yaml")),
    }
}

fn resolve_cwd_relative(cwd: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(candidate)
    }
}

fn default_home_dir(cwd: &Path, env: &BootEnvironment, _config_source: &ConfigSource) -> PathBuf {
    let home_base = env.user_home.clone().unwrap_or_else(|| cwd.to_path_buf());
    let standard = home_base.join(".config").join("mihomo");
    if standard.exists() {
        return standard;
    }

    if let Some(xdg) = &env.xdg_config_home {
        return xdg.join("mihomo");
    }

    standard
}
