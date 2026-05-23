use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;

use base64::Engine;
use blake3::hash as blake3_hash;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use mihomo_core::{push_log, LogLevel};
use mihomo_config::{Command, RuleProviderBehavior, RuleProviderFormat};
use ml_kem::{kem::KeyExport, ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey, Seed as MlKemSeed};
use rand_core::{OsRng, RngCore};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let options = match mihomo_config::parse_args(std::env::args()) {
        Ok(options) => options,
        Err(err) => {
            let message = format!("argument parse error: {err}");
            eprintln!("{message}");
            push_log(LogLevel::Error, message);
            std::process::exit(2);
        }
    };

    if options.show_version {
        print!("{}", render_version_output());
        return;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let environment = mihomo_config::BootEnvironment::from_process();

    match &options.command {
        Command::ConvertRuleset(args) => {
            if let Err(err) = run_convert_ruleset_command(args) {
                eprintln!("{err}");
                push_log(LogLevel::Error, err.clone());
                std::process::exit(3);
            }
            return;
        }
        Command::Generate(args) => {
            match run_generate_command(args) {
                Ok(output) => {
                    print!("{output}");
                    return;
                }
                Err(err) => {
                    eprintln!("{err}");
                    push_log(LogLevel::Error, err.clone());
                    std::process::exit(3);
                }
            }
        }
        Command::Run => {}
    }

    let options = match normalize_stdin_boot_options(options) {
        Ok(options) => options,
        Err(err) => {
            let message = format!("bootstrap error: {err}");
            eprintln!("{message}");
            push_log(LogLevel::Error, message);
            std::process::exit(1);
        }
    };

    let state = match mihomo_runtime::bootstrap_from_boot_options(
        &options,
        &cwd,
        &environment,
    ) {
        Ok(state) => state,
        Err(err) => {
            if options.test_config {
                eprintln!("{err}");
                push_log(LogLevel::Error, err.to_string());
                let resolved = options.resolve(&cwd, &environment);
                let message = render_test_config_failure(&resolved);
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                std::process::exit(1);
            }
            let message = format!("bootstrap error: {err}");
            eprintln!("{message}");
            push_log(LogLevel::Error, message);
            std::process::exit(1);
        }
    };
    if options.test_config {
        println!(
            "{}",
            render_test_config_success(&state.resolved_boot)
        );
        return;
    }

    let app = match mihomo_app::RunningApp::from_state(&options, state) {
        Ok(app) => app,
        Err(err) => {
            let message = format!("app start error: {err}");
            eprintln!("{message}");
            push_log(LogLevel::Error, message);
            std::process::exit(1);
        }
    };
    let _post_down_guard = PostDownGuard::new(options.post_down.clone());
    if let Some(post_up) = &options.post_up {
        if let Err(err) = exec_shell(post_up) {
            let message = format!("post-up script error: {err}");
            eprintln!("{message}");
            push_log(LogLevel::Error, message);
            std::process::exit(1);
        }
    }
    println!("{}", app.summary());
    if app.has_background_services() {
        match run_app_until_signal(app, &options, &cwd, &environment) {
            Ok(RunLoopExit::Shutdown) => {}
            Ok(RunLoopExit::Restart) => {
                if let Err(err) = restart_current_process() {
                    let message = format!("restart error: {err}");
                    eprintln!("{message}");
                    push_log(LogLevel::Error, message);
                    std::process::exit(1);
                }
            }
            Err(err) => {
                let message = format!("signal loop error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                std::process::exit(1);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunLoopExit {
    Shutdown,
    Restart,
}

fn render_version_output() -> String {
    let rust_version = option_env!("MIHOMO_RUSTC_VERSION").unwrap_or("rustc unknown");
    let build_time = option_env!("MIHOMO_BUILD_TIME").unwrap_or("unknown time");
    format!(
        "Mihomo Meta {} {} {} with {} {}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        rust_version,
        build_time,
    )
}

fn normalize_stdin_boot_options(options: mihomo_config::BootOptions) -> Result<mihomo_config::BootOptions, String> {
    let mut stdin = std::io::stdin().lock();
    normalize_stdin_boot_options_with_reader(options, &mut stdin)
}

fn normalize_stdin_boot_options_with_reader(
    mut options: mihomo_config::BootOptions,
    reader: &mut dyn Read,
) -> Result<mihomo_config::BootOptions, String> {
    if options.config_base64.is_some() || options.config_file.as_deref() != Some("-") {
        return Ok(options);
    }

    let mut config = Vec::new();
    reader.read_to_end(&mut config).map_err(|err| err.to_string())?;
    options.config_base64 = Some(base64::engine::general_purpose::STANDARD.encode(config));
    options.config_file = None;
    Ok(options)
}

fn render_test_config_success(resolved_boot: &mihomo_config::ResolvedBoot) -> String {
    format!(
        "configuration file {} test is successful",
        resolved_boot.config_display_path().display()
    )
}

fn render_test_config_failure(resolved_boot: &mihomo_config::ResolvedBoot) -> String {
    match &resolved_boot.config_source {
        mihomo_config::ConfigSource::File(path) => {
            format!("configuration file {} test failed", path.display())
        }
        mihomo_config::ConfigSource::Base64(_) | mihomo_config::ConfigSource::Stdin => {
            "configuration test failed".to_owned()
        }
    }
}

fn run_convert_ruleset_command(args: &[String]) -> Result<(), String> {
    if args.len() < 4 {
        return Err("Usage: convert-ruleset <behavior> <format> <source file> <target file>".into());
    }
    let behavior = parse_rule_behavior(&args[0])?;
    let format = parse_rule_format(&args[1])?;
    let source = PathBuf::from(&args[2]);
    let target = PathBuf::from(&args[3]);
    let source_bytes = fs::read(&source).map_err(|err| err.to_string())?;
    let converted =
        mihomo_rules::convert_ruleset_content(&source_bytes, behavior, format).map_err(|err| {
            err.to_string()
        })?;
    fs::write(target, converted).map_err(|err| err.to_string())
}

fn parse_rule_behavior(raw: &str) -> Result<RuleProviderBehavior, String> {
    match raw {
        "domain" => Ok(RuleProviderBehavior::Domain),
        "ipcidr" => Ok(RuleProviderBehavior::IpCidr),
        "classical" => Ok(RuleProviderBehavior::Classical),
        _ => Err(format!("unsupported behavior type: {raw}")),
    }
}

fn parse_rule_format(raw: &str) -> Result<RuleProviderFormat, String> {
    match raw {
        "" | "yaml" => Ok(RuleProviderFormat::Yaml),
        "text" => Ok(RuleProviderFormat::Text),
        "mrs" => Ok(RuleProviderFormat::Mrs),
        _ => Err(format!("unsupported format type: {raw}")),
    }
}

fn run_generate_command(args: &[String]) -> Result<String, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(
            "Using: generate uuid/reality-keypair/wg-keypair/ech-keypair/vless-mlkem768/vless-x25519/sudoku-keypair"
                .into(),
        );
    };
    match command {
        "uuid" => Ok(format!("{}\n", Uuid::new_v4())),
        "reality-keypair" => {
            let (private_key, public_key) = generate_x25519_keypair();
            Ok(format!(
                "PrivateKey: {}\nPublicKey: {}\n",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private_key),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
            ))
        }
        "wg-keypair" => {
            let (private_key, public_key) = generate_x25519_keypair();
            Ok(format!(
                "PrivateKey: {}\nPublicKey: {}\n",
                base64::engine::general_purpose::STANDARD.encode(private_key),
                base64::engine::general_purpose::STANDARD.encode(public_key),
            ))
        }
        "vless-x25519" => {
            let private_key = generate_or_parse_x25519_private_key(args.get(1).map(String::as_str))?;
            let secret = StaticSecret::from(private_key);
            let password = PublicKey::from(&secret).to_bytes();
            let hash32 = blake3_hash(&password);
            let private_key_base64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private_key);
            let password_base64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(password);
            let hash32_base64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash32.as_bytes());
            Ok(format!(
                "PrivateKey: {private_key_base64}\nPassword: {password_base64}\nHash32: {hash32_base64}\n-----------------------\n      Lazy-Config      \n-----------------------\n[Server] decryption: \"mlkem768x25519plus.native.600s.{private_key_base64}\"\n[Client] encryption: \"mlkem768x25519plus.native.0rtt.{password_base64}\"\n"
            ))
        }
        "ech-keypair" => {
            let Some(public_name) = args.get(1).map(String::as_str) else {
                return Err("Using: generate ech-keypair <plain_server_name>".into());
            };
            let (config_base64, key_pem) = generate_ech_keypair(public_name);
            Ok(format!("Config: {config_base64}\nKey: {key_pem}"))
        }
        "vless-mlkem768" => {
            let seed = generate_or_parse_mlkem768_seed(args.get(1).map(String::as_str))?;
            let dk = MlKem768DecapsulationKey::from_seed(seed);
            let client = dk.encapsulation_key().to_bytes();
            let hash32 = blake3_hash(client.as_slice());
            let seed_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed.as_slice());
            let client_base64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client.as_slice());
            let hash32_base64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash32.as_bytes());
            Ok(format!(
                "Seed: {seed_base64}\nClient: {client_base64}\nHash32: {hash32_base64}\n-----------------------\n      Lazy-Config      \n-----------------------\n[Server] decryption: \"mlkem768x25519plus.native.600s.{seed_base64}\"\n[Client] encryption: \"mlkem768x25519plus.native.0rtt.{client_base64}\"\n"
            ))
        }
        "sudoku-keypair" => {
            let (private_key, public_key) = generate_sudoku_keypair();
            Ok(format!(
                "PrivateKey: {private_key}\nPublicKey: {public_key}\n"
            ))
        }
        other => Err(format!(
            "generate subcommand is not implemented yet in the Rust rewrite: {other}"
        )),
    }
}

fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let private_key = generate_or_parse_x25519_private_key(None).expect("random x25519 key");
    let secret = StaticSecret::from(private_key);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn generate_or_parse_x25519_private_key(input: Option<&str>) -> Result<[u8; 32], String> {
    let mut private_key = [0_u8; 32];
    if let Some(input) = input.filter(|value| !value.is_empty()) {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| format!("invalid length of X25519 private key: {input}"))?;
        if decoded.len() != 32 {
            return Err(format!("invalid length of X25519 private key: {input}"));
        }
        private_key.copy_from_slice(&decoded);
    } else {
        OsRng.fill_bytes(&mut private_key);
    }
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    Ok(private_key)
}

fn generate_sudoku_keypair() -> (String, String) {
    let master = random_edwards_scalar();
    let public = (master * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let split_r = random_edwards_scalar();
    let split_k = master - split_r;
    let mut private = [0_u8; 64];
    private[..32].copy_from_slice(&split_r.to_bytes());
    private[32..].copy_from_slice(&split_k.to_bytes());
    (hex_encode(&private), hex_encode(&public))
}

fn generate_or_parse_mlkem768_seed(input: Option<&str>) -> Result<MlKemSeed, String> {
    let mut seed_bytes = [0_u8; 64];
    if let Some(input) = input.filter(|value| !value.is_empty()) {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| format!("invalid length of ML-KEM-768 seed: {input}"))?;
        if decoded.len() != 64 {
            return Err(format!("invalid length of ML-KEM-768 seed: {input}"));
        }
        seed_bytes.copy_from_slice(&decoded);
    } else {
        OsRng.fill_bytes(&mut seed_bytes);
    }
    Ok(seed_bytes.into())
}

fn generate_ech_keypair(public_name: &str) -> (String, String) {
    const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    const DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
    const KDF_HKDF_SHA256: u16 = 0x0001;
    const SORTED_SUPPORTED_AEADS: [u16; 3] = [0x0001, 0x0002, 0x0003];

    let (private_key, public_key) = generate_x25519_keypair();

    let mut inner = Vec::new();
    inner.push(0);
    push_u16(&mut inner, DHKEM_X25519_HKDF_SHA256);
    push_u16_len_prefixed(&mut inner, &public_key);

    let mut suites = Vec::new();
    for aead_id in SORTED_SUPPORTED_AEADS {
        push_u16(&mut suites, KDF_HKDF_SHA256);
        push_u16(&mut suites, aead_id);
    }
    push_u16_len_prefixed(&mut inner, &suites);
    inner.push(0);
    push_u8_len_prefixed(&mut inner, public_name.as_bytes());
    push_u16(&mut inner, 0);

    let mut ech_config = Vec::new();
    push_u16(&mut ech_config, EXTENSION_ENCRYPTED_CLIENT_HELLO);
    push_u16_len_prefixed(&mut ech_config, &inner);

    let mut ech_config_list = Vec::new();
    push_u16_len_prefixed(&mut ech_config_list, &ech_config);

    let mut ech_keys = Vec::new();
    push_u16_len_prefixed(&mut ech_keys, &private_key);
    push_u16_len_prefixed(&mut ech_keys, &ech_config);

    let config_base64 = base64::engine::general_purpose::STANDARD.encode(ech_config_list);
    let key_pem = pem_encode("ECH KEYS", &ech_keys);
    (config_base64, key_pem)
}

fn random_edwards_scalar() -> Scalar {
    let mut seed = [0_u8; 64];
    OsRng.fill_bytes(&mut seed);
    Scalar::from_bytes_mod_order_wide(&seed)
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(LUT[(byte >> 4) as usize] as char);
        output.push(LUT[(byte & 0x0f) as usize] as char);
    }
    output
}

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push_u16_len_prefixed(buf: &mut Vec<u8>, value: &[u8]) {
    push_u16(buf, value.len() as u16);
    buf.extend_from_slice(value);
}

fn push_u8_len_prefixed(buf: &mut Vec<u8>, value: &[u8]) {
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

fn pem_encode(label: &str, payload: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(payload);
    let mut pem = String::new();
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 body"));
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

struct PostDownGuard {
    command: Option<String>,
}

impl PostDownGuard {
    fn new(command: Option<String>) -> Self {
        Self { command }
    }
}

impl Drop for PostDownGuard {
    fn drop(&mut self) {
        if let Some(command) = self.command.take() {
            if let Err(err) = exec_shell(&command) {
                let message = format!("post-down script error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
            }
        }
    }
}

fn exec_shell(command: &str) -> Result<(), String> {
    #[cfg(unix)]
    let output = ProcessCommand::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|err| err.to_string())?;

    #[cfg(windows)]
    let output = ProcessCommand::new("cmd")
        .arg("/C")
        .arg(command)
        .output()
        .map_err(|err| err.to_string())?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if !stderr.is_empty() {
        stderr
    } else {
        stdout
    };
    if detail.is_empty() {
        Err(format!("command exited with status {}", output.status))
    } else {
        Err(format!("{detail} (status: {})", output.status))
    }
}

#[cfg(unix)]
fn run_app_until_signal(
    mut app: mihomo_app::RunningApp,
    options: &mihomo_config::BootOptions,
    cwd: &Path,
    environment: &mihomo_config::BootEnvironment,
) -> Result<RunLoopExit, String> {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP]).map_err(|err| err.to_string())?;
    loop {
        for signal in signals.pending() {
            match signal {
                SIGINT | SIGTERM => {
                    app.shutdown();
                    return Ok(RunLoopExit::Shutdown);
                }
                SIGHUP => match app.reload(options, cwd, environment) {
                    Ok(()) => println!("{}", app.summary()),
                    Err(err) => {
                        let message = format!("reload error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                    }
                },
                _ => {}
            }
        }
        if matches!(
            app.poll_control_command(),
            Some(mihomo_api::ApiControlCommand::Restart)
        ) {
            app.shutdown();
            return Ok(RunLoopExit::Restart);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(not(unix))]
fn run_app_until_signal(
    mut app: mihomo_app::RunningApp,
    _options: &mihomo_config::BootOptions,
    _cwd: &Path,
    _environment: &mihomo_config::BootEnvironment,
) -> Result<RunLoopExit, String> {
    loop {
        if matches!(
            app.poll_control_command(),
            Some(mihomo_api::ApiControlCommand::Restart)
        ) {
            app.shutdown();
            return Ok(RunLoopExit::Restart);
        }
        std::thread::park_timeout(Duration::from_secs(3600));
    }
}

#[cfg(unix)]
fn restart_current_process() -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    let err = ProcessCommand::new(&exe).args(std::env::args_os().skip(1)).exec();
    Err(err.to_string())
}

#[cfg(windows)]
fn restart_current_process() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    ProcessCommand::new(&exe)
        .args(std::env::args_os().skip(1))
        .spawn()
        .map_err(|err| err.to_string())?;
    std::process::exit(0);
}

#[cfg(not(any(unix, windows)))]
fn restart_current_process() -> Result<(), String> {
    Err("restart is not supported on this platform".to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpStream;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use mihomo_config::{BootEnvironment, BootOptions, Command, ConfigSource, ResolvedBoot};
    use mihomo_runtime::bootstrap_from_boot_options_with_stdin;
    use mihomo_app::RunningApp;

    use super::{
        exec_shell, normalize_stdin_boot_options_with_reader, render_test_config_failure,
        render_test_config_success, render_version_output, run_convert_ruleset_command,
        run_app_until_signal, run_generate_command, PostDownGuard, RunLoopExit,
    };

    #[test]
    fn convert_ruleset_command_writes_mrs_and_round_trips_to_text() {
        let temp = unique_temp_dir();
        let source = temp.join("rules.txt");
        let mrs = temp.join("rules.mrs");
        let text = temp.join("rules.out.txt");
        fs::write(&source, ".example.com\nsub.test\n").unwrap();

        run_convert_ruleset_command(&[
            "domain".into(),
            "text".into(),
            source.to_string_lossy().into_owned(),
            mrs.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let bytes = fs::read(&mrs).unwrap();
        assert!(!bytes.is_empty());

        run_convert_ruleset_command(&[
            "domain".into(),
            "mrs".into(),
            mrs.to_string_lossy().into_owned(),
            text.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let output = fs::read_to_string(text).unwrap();
        assert!(output.contains("+.example.com"));
        assert!(output.contains("sub.test"));
    }

    #[test]
    fn generate_command_outputs_uuid_and_x25519_keypairs() {
        let uuid = run_generate_command(&["uuid".into()]).unwrap();
        assert!(uuid.trim().len() >= 32);

        let reality = run_generate_command(&["reality-keypair".into()]).unwrap();
        let mut reality_lines = reality.lines();
        let private = reality_lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let public = reality_lines.next().unwrap().strip_prefix("PublicKey: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(private)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(public)
                .unwrap()
                .len(),
            32
        );

        let wg = run_generate_command(&["wg-keypair".into()]).unwrap();
        let mut wg_lines = wg.lines();
        let private = wg_lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let public = wg_lines.next().unwrap().strip_prefix("PublicKey: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(private)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(public)
                .unwrap()
                .len(),
            32
        );

        let vless = run_generate_command(&["vless-x25519".into()]).unwrap();
        let mut lines = vless.lines();
        let private = lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let password = lines.next().unwrap().strip_prefix("Password: ").unwrap();
        let hash32 = lines.next().unwrap().strip_prefix("Hash32: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(private)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(password)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(hash32)
                .unwrap()
                .len(),
            32
        );
        assert!(vless.contains("[Server] decryption:"));
        assert!(vless.contains("[Client] encryption:"));

        let sudoku = run_generate_command(&["sudoku-keypair".into()]).unwrap();
        let mut lines = sudoku.lines();
        let private = lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let public = lines.next().unwrap().strip_prefix("PublicKey: ").unwrap();
        assert_eq!(private.len(), 128);
        assert_eq!(public.len(), 64);
        assert!(private.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(public.chars().all(|c| c.is_ascii_hexdigit()));

        let ech = run_generate_command(&["ech-keypair".into(), "www.example.com".into()]).unwrap();
        let config = ech
            .lines()
            .next()
            .unwrap()
            .strip_prefix("Config: ")
            .unwrap();
        let public_name = parse_ech_public_name(config);
        assert_eq!(public_name, "www.example.com");
        assert!(ech.contains("-----BEGIN ECH KEYS-----"));
        assert!(ech.contains("-----END ECH KEYS-----"));

        let mlkem = run_generate_command(&["vless-mlkem768".into()]).unwrap();
        let mut lines = mlkem.lines();
        let seed = lines.next().unwrap().strip_prefix("Seed: ").unwrap();
        let client = lines.next().unwrap().strip_prefix("Client: ").unwrap();
        let hash32 = lines.next().unwrap().strip_prefix("Hash32: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(seed)
                .unwrap()
                .len(),
            64
        );
        assert!(!base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(client)
            .unwrap()
            .is_empty());
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(hash32)
                .unwrap()
                .len(),
            32
        );
        assert!(mlkem.contains("[Server] decryption:"));
        assert!(mlkem.contains("[Client] encryption:"));
    }

    #[test]
    fn version_output_matches_main_go_shape() {
        let output = render_version_output();
        assert!(output.starts_with("Mihomo Meta "));
        assert!(output.contains(" with rustc "));
        assert!(output.contains(" unknown time"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn test_config_messages_follow_main_go_file_shape() {
        let temp = unique_temp_dir();
        let resolved = ResolvedBoot {
            home_dir: temp.clone(),
            config_source: ConfigSource::File(temp.join("config.yaml")),
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        assert_eq!(
            render_test_config_success(&resolved),
            format!(
                "configuration file {} test is successful",
                temp.join("config.yaml").display()
            )
        );
        assert_eq!(
            render_test_config_failure(&resolved),
            format!(
                "configuration file {} test failed",
                temp.join("config.yaml").display()
            )
        );
    }

    #[test]
    fn test_config_failure_message_is_generic_for_non_file_sources() {
        let temp = unique_temp_dir();
        let stdin_resolved = ResolvedBoot {
            home_dir: temp.clone(),
            config_source: ConfigSource::Stdin,
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        let base64_resolved = ResolvedBoot {
            home_dir: temp,
            config_source: ConfigSource::Base64("cHJveGllczogW10K".into()),
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        assert_eq!(render_test_config_failure(&stdin_resolved), "configuration test failed");
        assert_eq!(render_test_config_failure(&base64_resolved), "configuration test failed");
    }

    #[test]
    fn stdin_config_source_bootstraps_from_dash_file_option() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some("-".into()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: true,
            command: Command::Run,
        };
        let yaml = br#"
proxies:
  - type: direct
    name: stdin-direct
"#;
        let mut stdin = Cursor::new(yaml.as_slice());
        let state = bootstrap_from_boot_options_with_stdin(
            &options,
            &temp,
            &BootEnvironment::default(),
            &mut stdin,
        )
        .unwrap();
        assert!(state.registry.proxies.contains_key("stdin-direct"));
        assert_eq!(
            state.resolved_boot.config_display_path(),
            temp.join("config.yaml")
        );
    }

    #[test]
    fn normalize_stdin_boot_options_inlines_dash_config_as_base64() {
        let options = BootOptions {
            home_dir: None,
            config_file: Some("-".into()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let yaml = br#"proxies:
  - type: direct
    name: stdin-normalized
"#;
        let expected = base64::engine::general_purpose::STANDARD.encode(yaml);
        let mut reader = Cursor::new(yaml.as_slice());
        let normalized = normalize_stdin_boot_options_with_reader(options, &mut reader).unwrap();
        assert_eq!(normalized.config_base64.as_deref(), Some(expected.as_str()));
        assert!(normalized.config_file.is_none());
    }

    #[test]
    fn normalized_stdin_boot_options_can_bootstrap_again_without_reader() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some("-".into()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let yaml = br#"
proxies:
  - type: direct
    name: stdin-reload-safe
"#;
        let mut reader = Cursor::new(yaml.as_slice());
        let normalized = normalize_stdin_boot_options_with_reader(options, &mut reader).unwrap();
        let state = bootstrap_from_boot_options_with_stdin(
            &normalized,
            &temp,
            &BootEnvironment::default(),
            &mut Cursor::new(Vec::<u8>::new()),
        )
        .unwrap();
        assert!(state.registry.proxies.contains_key("stdin-reload-safe"));
        assert_eq!(
            state.resolved_boot.config_display_path(),
            temp.join("config.yaml")
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_loop_returns_restart_when_controller_requests_restart() {
        let temp = unique_temp_dir();
        let config_path = temp.join("config.yaml");
        fs::write(
            &config_path,
            r#"
external-controller: 127.0.0.1:0
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(config_path.to_string_lossy().into_owned()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let env = BootEnvironment::default();
        let app = RunningApp::start(&options, &temp, &env).unwrap();
        let addr = app.controller_addr().unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(
                b"POST /restart HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"), "{response}");

        let outcome = run_app_until_signal(app, &options, &temp, &env).unwrap();
        assert_eq!(outcome, RunLoopExit::Restart);
    }

    #[test]
    #[cfg(unix)]
    fn shell_hooks_execute_post_up_and_post_down_commands() {
        let temp = unique_temp_dir();
        let up_path = temp.join("post-up.txt");
        let down_path = temp.join("post-down.txt");
        let up_cmd = format!("printf up > {}", shell_quote(&up_path));
        exec_shell(&up_cmd).unwrap();
        assert_eq!(fs::read_to_string(&up_path).unwrap(), "up");

        {
            let down_cmd = format!("printf down > {}", shell_quote(&down_path));
            let _guard = PostDownGuard::new(Some(down_cmd));
        }
        assert_eq!(fs::read_to_string(&down_path).unwrap(), "down");
    }

    fn parse_ech_public_name(config_base64: &str) -> String {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(config_base64)
            .unwrap();
        let mut cursor = 0_usize;
        let list_len = read_u16(&bytes, &mut cursor) as usize;
        assert_eq!(bytes.len() - cursor, list_len);
        let extension = read_u16(&bytes, &mut cursor);
        assert_eq!(extension, 0xfe0d);
        let config_len = read_u16(&bytes, &mut cursor) as usize;
        let config_end = cursor + config_len;
        let id = bytes[cursor];
        cursor += 1;
        assert_eq!(id, 0);
        assert_eq!(read_u16(&bytes, &mut cursor), 0x0020);
        let pub_len = read_u16(&bytes, &mut cursor) as usize;
        assert_eq!(pub_len, 32);
        cursor += pub_len;
        let suites_len = read_u16(&bytes, &mut cursor) as usize;
        assert_eq!(suites_len, 12);
        cursor += suites_len;
        let max_name_len = bytes[cursor];
        cursor += 1;
        assert_eq!(max_name_len, 0);
        let name_len = bytes[cursor] as usize;
        cursor += 1;
        let public_name = String::from_utf8(bytes[cursor..cursor + name_len].to_vec()).unwrap();
        cursor += name_len;
        assert_eq!(read_u16(&bytes, &mut cursor), 0);
        assert_eq!(cursor, config_end);
        public_name
    }

    fn read_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
        let value = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
        *cursor += 2;
        value
    }

    #[cfg(unix)]
    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn unique_temp_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mihomo-app-main-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
