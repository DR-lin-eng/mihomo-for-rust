use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use mihomo_config::{BootOptions, Command};
use mihomo_core::{push_log, LogLevel};
use mihomo_runtime::{BootstrapState, NativeSupportGap};

pub(crate) fn render_native_support_gap_error(gaps: &[NativeSupportGap]) -> String {
    let mut lines = vec![
        "native Rust runtime does not yet support one or more configured proxy protocols or features:".to_owned(),
    ];
    for gap in gaps {
        let kind = gap
            .kind
            .map(|kind| format!(" type={}", kind.as_str()))
            .unwrap_or_default();
        let provider = if gap.provider_name.is_empty() {
            String::new()
        } else {
            format!(" provider={}", gap.provider_name)
        };
        lines.push(format!(
            "- proxy={}{}{} reason={}",
            gap.proxy_name, kind, provider, gap.reason
        ));
    }
    lines.push("falling back to the legacy Go runtime for this configuration".to_owned());
    lines.join("\n")
}

pub(crate) fn hand_off_to_legacy_runtime(
    options: &BootOptions,
    gaps: &[NativeSupportGap],
    state: &BootstrapState,
) -> Result<(), String> {
    let legacy_runtime = resolve_legacy_runtime()?;
    let args = legacy_runtime_args(options, gaps);
    let env_overrides = legacy_runtime_env_overrides(state)?;
    let notice = render_native_support_gap_error(gaps);
    eprintln!("{notice}");
    push_log(LogLevel::Warn, notice);
    exec_legacy_runtime(&legacy_runtime, &args, &env_overrides)
}

pub(crate) fn legacy_runtime_args(
    options: &BootOptions,
    gaps: &[NativeSupportGap],
) -> Vec<std::ffi::OsString> {
    let mut args = Vec::new();
    match &options.command {
        Command::Run => {}
        Command::ConvertRuleset(values) => {
            args.push("convert-ruleset".into());
            args.extend(values.iter().cloned().map(Into::into));
            return args;
        }
        Command::Generate(values) => {
            args.push("generate".into());
            args.extend(values.iter().cloned().map(Into::into));
            return args;
        }
    }

    let legacy_home = options
        .home_dir
        .clone()
        .or_else(|| derive_legacy_home_dir().ok())
        .or_else(|| fallback_legacy_home_dir(gaps));
    push_flag_value(&mut args, "-d", legacy_home.as_deref());
    if let Some(config_base64) = &options.config_base64 {
        push_flag_value(&mut args, "-config", Some(config_base64));
    } else {
        push_flag_value(&mut args, "-f", options.config_file.as_deref());
    }
    push_flag_value(&mut args, "-ext-ui", options.external_ui.as_deref());
    push_flag_value(&mut args, "-ext-ctl", options.external_controller.as_deref());
    push_flag_value(
        &mut args,
        "-ext-ctl-unix",
        options.external_controller_unix.as_deref(),
    );
    push_flag_value(
        &mut args,
        "-ext-ctl-pipe",
        options.external_controller_pipe.as_deref(),
    );
    push_flag_value(&mut args, "-secret", options.secret.as_deref());
    push_flag_value(&mut args, "-post-up", options.post_up.as_deref());
    push_flag_value(&mut args, "-post-down", options.post_down.as_deref());
    if options.geodata_mode {
        args.push("-m".into());
    }
    if options.show_version {
        args.push("-v".into());
    }
    if options.test_config {
        args.push("-t".into());
    }
    args
}

fn resolve_legacy_runtime() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("MIHOMO_LEGACY_BINARY") {
        let candidate = PathBuf::from(explicit);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
        return Err(format!(
            "MIHOMO_LEGACY_BINARY points to a missing or non-executable file: {}",
            candidate.display()
        ));
    }

    let mut search_roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        search_roots.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        let exe_dir = exe
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "failed to resolve current executable directory".to_owned())?;
        search_roots.push(exe_dir.clone());
        if let Some(parent) = exe_dir.parent() {
            search_roots.push(parent.to_path_buf());
        }
    }

    let executable_names = if cfg!(windows) {
        vec!["mihomo-legacy.exe", "mihomo-go-legacy.exe"]
    } else {
        vec![
            "mihomo-legacy",
            "mihomo-go-legacy",
            "Clash1.Core",
            "Clash.Core.backup",
        ]
    };

    for root in search_roots {
        for name in &executable_names {
            for candidate in [
                root.join(name),
                root.join("bin").join(name),
                root.join("legacy").join(name),
            ] {
                if is_executable_file(&candidate) {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(
        "no legacy Go runtime binary was found; build one with `go build -tags \"legacy_go_runtime with_gvisor\" -o bin/mihomo-legacy` or set MIHOMO_LEGACY_BINARY".to_owned(),
    )
}

fn derive_legacy_home_dir() -> Result<String, String> {
    let cwd = std::env::current_dir().map_err(|err| err.to_string())?;
    Ok(cwd.join(".mihomo-legacy").to_string_lossy().into_owned())
}

fn fallback_legacy_home_dir(gaps: &[NativeSupportGap]) -> Option<String> {
    let suffix = gaps
        .first()
        .map(|gap| gap.proxy_name.replace(['/', '\\', ' ', ':'], "-"))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".to_owned());
    Some(
        std::env::temp_dir()
            .join(format!("mihomo-legacy-{suffix}"))
            .to_string_lossy()
            .into_owned(),
    )
}

fn legacy_runtime_env_overrides(state: &BootstrapState) -> Result<Vec<(String, String)>, String> {
    let mapping = mihomo_app::selected_proxy_mapping_from_state(state);
    let payload = serde_json::to_string(&mapping).map_err(|err| err.to_string())?;
    Ok(vec![(mihomo_app::SELECTED_PROXY_ENV.to_owned(), payload)])
}

fn push_flag_value(args: &mut Vec<std::ffi::OsString>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.push(flag.into());
        args.push(value.into());
    }
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if metadata.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(unix)]
fn exec_legacy_runtime(
    path: &Path,
    args: &[std::ffi::OsString],
    env_overrides: &[(String, String)],
) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let mut command = ProcessCommand::new(path);
    command.args(args);
    for (key, value) in env_overrides {
        command.env(key, value);
    }
    let err = command.exec();
    Err(err.to_string())
}

#[cfg(windows)]
fn exec_legacy_runtime(
    path: &Path,
    args: &[std::ffi::OsString],
    env_overrides: &[(String, String)],
) -> Result<(), String> {
    let mut command = ProcessCommand::new(path);
    command.args(args);
    for (key, value) in env_overrides {
        command.env(key, value);
    }
    command.spawn().map_err(|err| err.to_string())?;
    std::process::exit(0);
}

#[cfg(not(any(unix, windows)))]
fn exec_legacy_runtime(
    path: &Path,
    args: &[std::ffi::OsString],
    env_overrides: &[(String, String)],
) -> Result<(), String> {
    let mut command = ProcessCommand::new(path);
    command.args(args);
    for (key, value) in env_overrides {
        command.env(key, value);
    }
    let status = command.status().map_err(|err| err.to_string())?;
    std::process::exit(status.code().unwrap_or(1));
}
