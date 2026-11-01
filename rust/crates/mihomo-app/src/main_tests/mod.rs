use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use mihomo_app::RunningApp;
use mihomo_config::{BootEnvironment, BootOptions, Command, ConfigSource, ResolvedBoot};
use mihomo_runtime::{
    bootstrap_from_boot_options, bootstrap_from_boot_options_with_stdin,
    detect_native_support_gaps,
};

use super::{
    exec_shell, legacy_runtime_args, normalize_stdin_boot_options_with_reader,
    render_top_level_tun_support_report,
    render_native_support_gap_error, render_test_config_failure, render_test_config_success,
    render_version_output, run_app_until_signal, run_convert_ruleset_command,
    run_generate_command, PostDownGuard, RunLoopExit,
};

include!("commands_and_bootstrap.rs");
include!("support_and_surfaces_native_support.rs");
include!("support_and_surfaces_legacy_fallback.rs");
include!("support_and_surfaces_listener_surface.rs");
include!("dns_and_process.rs");
include!("helpers.rs");
