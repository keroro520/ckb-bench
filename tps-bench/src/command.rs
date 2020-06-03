use crate::config::Config;
use std::time::Duration;

pub const MINE_SUBCOMMAND: &str = "mine";
pub const BENCH_SUBCOMMAND: &str = "bench";
pub const INIT_BENCH_ACCOUNT_SUBCOMMAND: &str = "init_bench_account";

pub enum CommandLine {
    MineMode(Config, u64 /* blocks */),
    BenchMode(Config, Duration /* duration */),
    InitBenchAccount(Config),
}

pub fn commandline() -> CommandLine {
    include_str!("../Cargo.toml");
    let matches = clap::app_from_crate!()
        .arg(clap::Arg::from_usage(
            "-c, --config <FILE> 'set config file'",
        ))
        .subcommand(
            clap::SubCommand::with_name(MINE_SUBCOMMAND)
                .about("start miner and exit after generating corresponding blocks")
                .arg(
                    clap::Arg::from_usage(
                        "-b --blocks <NUMBER> 'the number of blocks to generate'",
                    )
                    .required(true)
                    .validator(|s| s.parse::<u64>().map(|_| ()).map_err(|err| err.to_string())),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name(BENCH_SUBCOMMAND)
                .about("start bencher and continuously send transactions for the duration")
                .arg(
                    clap::Arg::from_usage("--seconds <NUMBER> 'the seconds to bench'")
                        .required(true)
                        .validator(|s| s.parse::<u64>().map(|_| ()).map_err(|err| err.to_string())),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name(INIT_BENCH_ACCOUNT_SUBCOMMAND)
                .about("init cells for bench account"),
        )
        .get_matches();

    let config = {
        let filepath = matches.value_of("config").unwrap_or("config.toml");
        match Config::load(filepath) {
            Ok(config) => config,
            Err(err) => prompt_and_exit!("Config::load error: {}", err),
        }
    };
    match matches.subcommand() {
        (MINE_SUBCOMMAND, Some(options)) => {
            let str = options
                .value_of("blocks")
                .expect("clap arg option `required(true)` checked");
            let blocks = str
                .parse::<u64>()
                .expect("clap arg option `validator` checked");
            CommandLine::MineMode(config, blocks)
        }
        (BENCH_SUBCOMMAND, Some(options)) => {
            let str = options
                .value_of("seconds")
                .expect("clap arg option `required(true)` checked");
            let seconds = str
                .parse::<u64>()
                .expect("clap arg option `validator` checked");
            let duration = Duration::from_secs(seconds);
            CommandLine::BenchMode(config, duration)
        }
        (INIT_BENCH_ACCOUNT_SUBCOMMAND, _) => CommandLine::InitBenchAccount(config),
        (subcommand, options) => {
            prompt_and_exit!(
                "unsupported subcommand: `{}`, options: {:?}",
                subcommand,
                options
            );
        }
    }
}
