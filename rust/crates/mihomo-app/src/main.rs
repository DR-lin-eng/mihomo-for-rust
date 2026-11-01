use mihomo_core::{push_log, LogLevel};
use mihomo_config::Command;

mod native_support;
mod main_commands;
mod main_process;
use mihomo_app::startup_trace;
use native_support::{
    effective_native_support_gaps, hand_off_to_legacy_runtime,
    render_top_level_tun_support_report,
    render_native_support_gap_error, should_abort_on_native_support_gaps,
    should_fallback_to_legacy,
};
#[cfg(test)]
pub(crate) use native_support::legacy_runtime_args;
pub(crate) use main_commands::{
    normalize_stdin_boot_options, render_test_config_failure, render_test_config_success,
    render_version_output, run_convert_ruleset_command, run_generate_command,
};
#[cfg(test)]
pub(crate) use main_commands::normalize_stdin_boot_options_with_reader;
pub(crate) use main_process::{
    exec_shell, restart_current_process, run_app_until_signal, PostDownGuard, RunLoopExit,
};

fn main() {
    startup_trace::mark("main:start");
    let options = match mihomo_config::parse_args(std::env::args()) {
        Ok(options) => options.with_process_environment(),
        Err(mihomo_config::ParseError::HelpRequested) => {
            println!("Usage: mihomo [options]\n  -d <directory>     Configuration/data directory\n  -f <file>          Configuration file (- for stdin)\n  -config <base64>   Base64 configuration\n  -ext-ui <path>     External dashboard directory\n  -ext-ctl <address> Controller HTTP address\n  -ext-ctl-unix <path> Controller Unix socket\n  -ext-ctl-pipe <name> Controller named pipe (unsupported in Rust runtime)\n  -secret <value>    Controller secret\n  -post-up <command> / -post-down <command>\n  -m                Enable geodata mode\n  -t                Validate configuration and exit\n  -v                Show version\n  -h                Show help");
            return;
        }
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
    startup_trace::mark("main:boot-env-ready");

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
    startup_trace::mark("main:stdin-normalized");

    let mut state = match mihomo_runtime::bootstrap_from_boot_options(
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
        if let Err(err) = state.build_runtime_tunnel().map(|_| ()).map_err(|err| err.to_string())
            .and_then(|_| state.build_dns_runtime().map(|_| ()).map_err(|err| err.to_string())) {
            eprintln!("{err}\n{}", render_test_config_failure(&state.resolved_boot));
            std::process::exit(1);
        }
    }
    startup_trace::mark("main:bootstrap-finished");
    mihomo_app::restore_selected_proxy_mapping(&mut state);
    startup_trace::mark("main:selected-proxy-restored");
    let native_support_gaps = effective_native_support_gaps(&state);
    startup_trace::mark("main:native-support-gaps-ready");
    if should_fallback_to_legacy(&options, &native_support_gaps) {
        match hand_off_to_legacy_runtime(&options, &native_support_gaps, &state) {
            Ok(()) => unreachable!("legacy runtime handoff should not return"),
            Err(err) => {
                let message = format!(
                    "{}\nlegacy runtime handoff error: {err}",
                    render_native_support_gap_error(&native_support_gaps),
                );
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
                std::process::exit(1);
            }
        }
    }
    if should_abort_on_native_support_gaps(&options, &native_support_gaps) {
        let message = render_native_support_gap_error(&native_support_gaps);
        eprintln!("{message}");
        push_log(LogLevel::Error, message);
        std::process::exit(1);
    }
    if options.test_config {
        let mut notices = Vec::new();
        if let Some(report) = render_top_level_tun_support_report(&state) {
            notices.push(report);
        }
        if !native_support_gaps.is_empty() {
            notices.push(render_native_support_gap_error(&native_support_gaps));
        }
        let native_support_notice = if notices.is_empty() {
            None
        } else {
            Some(notices.join("\n"))
        };
        println!(
            "{}",
            render_test_config_success(&state.resolved_boot, native_support_notice.as_deref())
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
    startup_trace::mark("main:app-started");
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

#[cfg(test)]
#[path = "main_tests/mod.rs"]
mod tests;
