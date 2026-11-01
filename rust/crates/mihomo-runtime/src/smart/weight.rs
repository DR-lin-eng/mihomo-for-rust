//! Adaptive fallback scoring follows the upstream Smart scene weights.
use super::features::ModelInput;

pub fn calculate(input: &ModelInput, priority: f64, now: u64) -> f64 {
    if input.success + input.failure < 2 {
        return 0.0;
    }
    let (u, d, ur, dr, t) = (
        input.upload_mb,
        input.download_mb,
        input.max_upload_kb,
        input.max_download_kb,
        input.duration_minutes,
    );
    let latency = input.latency;
    let total_rate = (u + d) / t;
    let scene = if (input.is_udp
        && latency < 150.0
        && t > 3.0
        && u > 0.2
        && d > 0.2
        && ur > 200.0
        && dr > 200.0
        && total_rate > 0.1
        && total_rate < 10.0)
        || (!input.is_udp
            && latency < 250.0
            && t > 3.0
            && u > 0.1
            && d > 0.1
            && u < 150.0
            && d < 150.0
            && u / d > 0.2
            && u / d < 5.0
            && ur > 150.0
            && dr > 150.0
            && total_rate > 0.05
            && total_rate < 15.0)
    {
        1
    } else if (u > 100.0 || d > 100.0 || ur > 5000.0) && t > 0.5 && total_rate > 5.0 {
        3
    } else if t > 1.0
        && ((d > 60.0 && d / u > 3.0 && dr > 2000.0 && dr / ur > 4.0 && d / t > 5.0)
            || (d > 15.0 && d / u > 3.0 && dr > 1000.0 && dr / ur > 3.0 && d / t > 2.0))
    {
        2
    } else {
        0
    };
    let mut params = match scene {
        1 => [0.6, 0.1, 0.3, 1.2, 1.0, 1.3, 0.5, 0.3],
        2 => [0.5, 0.2, 0.3, 1.5, 0.8, 1.2, 0.8, 0.2],
        3 => [0.5, 0.2, 0.3, 1.8, 0.7, 0.9, 1.0, 0.1],
        _ => [0.5, 0.1, 0.4, 0.8, 0.6, 1.0, 0.3, 0.2],
    };
    let decay = if input.last_used == 0 {
        1.0
    } else {
        let hours = now.saturating_sub(input.last_used / 3600 * 3600) as f64 / 3600.0;
        let value = if hours <= 24.0 {
            1.0
        } else if hours <= 72.0 {
            1.0 - (hours - 24.0) / 48.0 * 0.2
        } else if hours <= 168.0 {
            0.8 - (hours - 72.0) / 96.0 * 0.3
        } else if hours <= 720.0 {
            0.5 - (hours - 168.0) / 552.0 * 0.2
        } else {
            0.1
        };
        value.max(params[7])
    };
    let (mut successes, mut failures) =
        (input.success as f64 * decay, input.failure as f64 * decay);
    if successes + failures < 1.0 {
        successes = successes.max(0.5);
        failures = failures.max(0.5);
    }
    let connect = if input.connect_time > 0.0 {
        input.connect_time
    } else if input.connection_failed {
        2000.0
    } else {
        1.0
    };
    let latency = if latency > 0.0 {
        latency
    } else if input.connection_failed {
        2000.0
    } else {
        1.0
    };
    let connect_score = ((-connect / 1500.0).exp() * decay).clamp(0.3, 0.8);
    let latency_score = ((-latency / 1500.0).exp() * decay).clamp(0.3, 0.8);
    if input.is_udp {
        params[2] = (params[2] * 1.2).min(0.5);
        params[0] = (params[0] * 1.1).min(0.6);
        params[1] = 1.0 - params[0] - params[2];
    }
    let success_rate = successes / (successes + failures);
    let base = success_rate * params[0] + connect_score * params[1] + latency_score * params[2];
    let short = t <= 1.0;
    let long = t > 10.0;
    let traffic = if u > 0.0 || d > 0.0 {
        let upload = traffic_factor(
            u,
            ur,
            t,
            input.history_max_upload_kb,
            input.history_upload_mb,
            input.history_duration_minutes,
            short,
        );
        let download = traffic_factor(
            d,
            dr,
            t,
            input.history_max_download_kb,
            input.history_download_mb,
            input.history_duration_minutes,
            short,
        );
        let uw = if scene == 2 {
            0.2
        } else if scene == 3 && u > d * 2.0 {
            0.7
        } else {
            0.4
        };
        upload * uw + download * (1.0 - uw)
    } else {
        0.0
    };
    let duration = if t <= 0.0 {
        0.1
    } else if short {
        (0.1 + t.ln_1p() * 0.08).min(0.3)
    } else if long {
        (0.2 + t.ln_1p() * 0.1).min(0.5)
    } else {
        (0.15 + t.ln_1p() * 0.09).min(0.4)
    };
    let mut quality = 0.0f64;
    if latency > 0.0 && latency < 100.0 {
        quality += 0.1;
    }
    if connect > 0.0 && connect < 10.0 {
        quality += 0.1;
    }
    if (scene == 2 || scene == 3) && d > 20.0 {
        quality += 0.1;
    }
    if scene == 1 && latency < 100.0 && success_rate > 0.9 {
        quality += 0.1;
    }
    let current = 1.0 - (-input.loss_rate * 10.0).exp();
    let cumulative = 1.0 - (-input.cumul_loss_rate * 50.0).exp();
    let trust = (cumulative * 5.0).min(1.0);
    let ema = 1.0 - (-input.ema_loss_rate * 50.0).exp();
    let improvement = if cumulative > 0.0 && ema > 0.0 && ema < cumulative {
        ema / cumulative
    } else {
        1.0
    };
    let loss = trust * current.max(cumulative) * improvement + (1.0 - trust) * current * 0.3;
    (base
        * (1.0 + traffic * params[3] + duration * params[4] + quality.min(0.3) * params[5]
            - loss * params[6])
        * priority)
        .max(0.0)
}
fn traffic_factor(
    mb: f64,
    rate: f64,
    duration: f64,
    history_rate: f64,
    history_mb: f64,
    history_duration: f64,
    short: bool,
) -> f64 {
    if mb <= 0.0 || duration <= 0.0 {
        return 0.0;
    }
    let ranges = [
        (0.005, 0.10, 0.05, 0.001),
        (0.01, 0.18, 0.08, 0.005),
        (0.05, 0.35, 0.10, 0.01),
        (0.1, 0.53, 0.15, 0.05),
        (0.5, 0.72, 0.18, 0.1),
        (1.0, 0.98, 0.15, 0.5),
        (5.0, 1.18, 0.10, 1.0),
        (20.0, 1.32, 0.08, 5.0),
        (100.0, 1.45, 0.06, 20.0),
        (500.0, 1.56, 0.05, 100.0),
        (3000.0, 1.66, 0.04, 500.0),
    ];
    let (_, base, slope, start) = ranges.into_iter().find(|range| mb < range.0).unwrap_or((
        f64::INFINITY,
        1.74,
        0.02,
        3000.0,
    ));
    let base = base + slope * (mb / start).log10();
    let rate_bonus = if rate < 20.0 {
        1.0 + 0.05 * rate / 20.0
    } else if rate < 100.0 {
        1.05 + 0.05 * (rate - 20.0) / 80.0
    } else if rate < 500.0 {
        1.10 + 0.05 * (rate - 100.0) / 400.0
    } else if rate < 2000.0 {
        1.15 + 0.05 * (rate - 500.0) / 1500.0
    } else if rate < 5000.0 {
        1.20 + 0.04 * (rate - 2000.0) / 3000.0
    } else if rate < 20000.0 {
        1.24 + 0.04 * (rate - 5000.0) / 15000.0
    } else if rate < 100000.0 {
        (1.28 + 0.03 * (rate / 20000.0).log10()).min(1.32)
    } else {
        (1.32 + 0.02 * (rate / 100000.0).log10()).min(1.36)
    };
    let throughput = mb * 1024.0 / (duration * 60.0).max(1.0);
    let acceleration = if throughput > 0.0 && rate / throughput > 2.0 {
        1.0 + (0.02 * (rate / throughput - 2.0)).min(0.12)
    } else {
        1.0
    };
    let history = if history_rate > 0.0 {
        let ratio = rate / history_rate;
        if ratio < 0.5 {
            0.6 + 0.4 * ratio
        } else if ratio < 0.9 {
            0.85 + 0.15 * ratio
        } else if ratio > 1.2 {
            1.0 + (0.02 * (ratio - 1.2)).min(0.05)
        } else {
            1.0
        }
    } else {
        1.0
    };
    let mut combined = rate_bonus * acceleration * history;
    if history_rate > 0.0 {
        let avg = if history_mb > 0.0 && history_duration > 0.0 {
            history_mb * 1024.0 / (history_duration * 60.0).max(1.0)
        } else {
            0.0
        };
        if rate / history_rate < 0.1
            && ((avg > 0.0 && throughput < avg * 0.3) || (avg == 0.0 && throughput < 10.0))
        {
            let evidence = if history_duration > 0.0 {
                ((history_duration / duration - 1.0) / 4.0).clamp(0.0, 1.0)
            } else {
                0.0
            };
            combined *= 1.0 - 0.5 * evidence;
        }
    }
    combined = combined.min(1.25);
    let rate_per_min = mb / duration.max(1.0);
    let connection = if short {
        1.0 + 0.06 * (rate_per_min / 25.0).min(1.0)
    } else if rate_per_min > 5.0 {
        1.0 + 0.05 * ((rate_per_min - 5.0) / 80.0).min(1.0)
    } else {
        1.0
    };
    (base * combined * connection).min(1.25)
}
