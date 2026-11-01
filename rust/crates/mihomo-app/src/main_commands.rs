use std::fs;
use std::io::Read;
use std::path::PathBuf;

use base64::Engine;
use blake3::hash as blake3_hash;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use mihomo_config::{RuleProviderBehavior, RuleProviderFormat};
use ml_kem::{
    kem::KeyExport, ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey, Seed as MlKemSeed,
};
use rand_core::{OsRng, RngCore};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) fn render_version_output() -> String {
    let rust_version = option_env!("MIHOMO_RUSTC_VERSION").unwrap_or("rustc unknown");
    let build_time = option_env!("MIHOMO_BUILD_TIME").unwrap_or("unknown time");
    let variants = mihomo_runtime::build_runtime_plan(&mihomo_config::BootOptions::default())
        .optimization_variants
        .into_iter()
        .map(|variant| variant.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "Mihomo Meta {} {} {} with {} {} variants={} {}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        rust_version,
        build_time,
        variants,
        if cfg!(target_os="linux"){ "smart ebpf" }else{ "smart" },
    )
}

pub(crate) fn normalize_stdin_boot_options(
    options: mihomo_config::BootOptions,
) -> Result<mihomo_config::BootOptions, String> {
    let mut stdin = std::io::stdin().lock();
    normalize_stdin_boot_options_with_reader(options, &mut stdin)
}

pub(crate) fn normalize_stdin_boot_options_with_reader(
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

pub(crate) fn render_test_config_success(
    resolved_boot: &mihomo_config::ResolvedBoot,
    native_support_notice: Option<&str>,
) -> String {
    let mut message = format!(
        "configuration file {} test is successful",
        resolved_boot.config_display_path().display()
    );
    if let Some(notice) = native_support_notice.filter(|notice| !notice.trim().is_empty()) {
        message.push('\n');
        message.push_str(notice.trim());
    }
    message
}

pub(crate) fn render_test_config_failure(resolved_boot: &mihomo_config::ResolvedBoot) -> String {
    match &resolved_boot.config_source {
        mihomo_config::ConfigSource::File(path) => {
            format!("configuration file {} test failed", path.display())
        }
        mihomo_config::ConfigSource::Base64(_) | mihomo_config::ConfigSource::Stdin => {
            "configuration test failed".to_owned()
        }
    }
}

pub(crate) fn run_convert_ruleset_command(args: &[String]) -> Result<(), String> {
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

pub(crate) fn run_generate_command(args: &[String]) -> Result<String, String> {
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
            let private_key =
                generate_or_parse_x25519_private_key(args.get(1).map(String::as_str))?;
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
            let seed_base64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed.as_slice());
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
