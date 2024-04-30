pub mod data;
#[cfg(feature = "hustoj")]
mod data_hustoj;
mod data_mock;
mod error;
pub mod util;

pub mod prelude {
    pub use crate::error::{Error, Result};
    pub use crate::util;
    pub use byte_unit::Byte;
    pub use byte_unit::Unit::{KiB, MiB};
    pub use cfg_if::cfg_if;
    pub use log::{debug, error, info, trace, warn};
    pub use serde::Deserialize;
    pub use std::fs::{create_dir, create_dir_all, File};
    pub use std::num::NonZeroU64;
    pub use std::path::{Path, PathBuf};
    pub use std::time::Duration;
}

use clap::{Args, Parser, ValueEnum};
use data::Verdict;
use prelude::*;
use std::process::exit;

#[derive(Clone, Copy, Debug, Deserialize, ValueEnum)]
enum DataSource {
    HustOJ,
    Mock,
}

fn fifteen_sec() -> Duration {
    Duration::from_secs(15)
}

fn one_gib() -> Byte {
    Byte::GIBIBYTE
}

fn thirty_two_mib() -> Byte {
    Byte::from_i64_with_unit(32, MiB).unwrap()
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize)]
struct RunLimit {
    #[serde_as(as = "serde_with::DurationSeconds<f64>")]
    #[serde(default = "fifteen_sec")]
    time: Duration,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    #[serde(default = "one_gib")]
    memory: Byte,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    #[serde(default = "thirty_two_mib")]
    output: Byte,
    #[serde(skip)]
    rt: bool,
}

impl Default for RunLimit {
    /// Default value is rational for compilers and compare scripts, but
    /// obviously too large for submission code.
    fn default() -> Self {
        Self {
            time: fifteen_sec(),
            memory: one_gib(),
            output: thirty_two_mib(),
            rt: false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Lang {
    /// Source code should be saved into this file
    src_name: String,
    /// Command to compile
    cmd_compile: Vec<String>,
    /// Command to run
    cmd_run: Vec<String>,
}

#[derive(Debug, Default, Args, Deserialize)]
struct Flags {
    #[clap(long, value_enum)]
    data_source: Option<DataSource>,
    /// Don't store judge result.
    #[clap(long)]
    #[serde(default)]
    dry: Option<bool>,
    /// Runtime dir.
    #[clap(long)]
    run_dir: Option<PathBuf>,
    /// Chroot dir.
    #[clap(long)]
    chroot_dir: Option<PathBuf>,
    /// Slice containing jobs.
    #[clap(long)]
    slice: Option<String>,
}

#[derive(Debug, Parser)]
struct Cli {
    /// The solution to be judged.
    solution_id: String,
    /// The name of the runner.
    runner_id: String,
    /// OJ runtime directory.
    oj_base: PathBuf,
    /// If specified, same as --stderr.
    debug: Option<String>,
    /// Override config file
    #[clap(long)]
    etc: Option<PathBuf>,

    #[clap(flatten)]
    cfg: Flags,
}

fn diff_zu() -> Vec<String> {
    ["/usr/bin/diff", "-Zu", "--color=auto"].into_iter().map(String::from).collect()
}

fn stack_inf() -> Byte {
    Byte::from(u64::MAX)
}

fn thirty_two() -> NonZeroU64 {
    NonZeroU64::try_from(32).unwrap()
}

fn home_judge() -> PathBuf {
    "/home/judge".into()
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Hust {
    #[serde(default)]
    db_url: String,
    #[serde(default = "home_judge")]
    oj_home: PathBuf,
}

impl Default for Hust {
    fn default() -> Self {
        Self {
            db_url: String::new(),
            oj_home: home_judge(),
        }
    }
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    config: Flags,
    #[serde(default)]
    language: std::collections::HashMap<String, Lang>,
    #[serde(default)]
    compiler_limit: RunLimit,
    #[serde(default)]
    compare_limit: RunLimit,
    #[serde(default = "diff_zu")]
    default_cmp: Vec<String>,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    #[serde(default = "stack_inf")]
    stack_limit: Byte,
    #[serde(default = "thirty_two")]
    nofile_limit: NonZeroU64,
    #[cfg(feature = "hustoj")]
    #[serde(default)]
    hust: Hust,
}

impl ConfigFile {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = util::load_file(path)?;
        toml::from_str(&content).map_err(Error::TOMLParseError)
    }
}

async fn run<P1: AsRef<Path>, P2: AsRef<Path>>(
    cli: &Cli,
    etc: &ConfigFile,
    lim: &RunLimit,
    mut cmd: Vec<String>,
    root: P1,
    (tmp, tmp_rw): (P2, bool),
    stdfd: [Option<&PathBuf>; 3],
) -> Result<systemd_run::FinishedRun> {
    let mem_lim_str = lim.memory.as_u64().to_string();
    for x in &mut cmd {
        *x = x.replace("%m", &mem_lim_str);
    }

    use util::ensure_utf8_path as u8p;
    let stdin = stdfd[0].map_or_else(
        || Ok(systemd_run::InputSpec::null()),
        |x| Ok(systemd_run::InputSpec::file(u8p(&x)?)),
    )?;
    let stdout = stdfd[1].map_or_else(
        || Ok(systemd_run::OutputSpec::null()),
        |x| Ok(systemd_run::OutputSpec::truncate(u8p(&x)?)),
    )?;
    let stderr = stdfd[2].map_or_else(
        || Ok(systemd_run::OutputSpec::null()),
        |x| Ok(systemd_run::OutputSpec::truncate(u8p(&x)?)),
    )?;
    let mut tmp = systemd_run::Mount::bind(u8p(&tmp)?);
    if tmp_rw {
        tmp = tmp.writable();
    }

    let prefix = cli
        .cfg
        .slice
        .as_deref()
        .or(etc.config.slice.as_deref())
        .unwrap_or("opoj");

    let slice = prefix.to_owned() + "-" + &cli.runner_id + ".slice";
    let ns = prefix.to_owned() + "-empty-ns@" + &cli.runner_id + ".service";

    let service_name = [
        "opoj-runner",
        &cli.runner_id,
        &uuid::Uuid::new_v4().simple().to_string(),
    ]
    .join("-");

    let sched = if lim.rt {
        systemd_run::CpuScheduling::round_robin_default_priority()
    } else {
        systemd_run::CpuScheduling::default()
    };

    systemd_run::RunSystem::new(&cmd[0])
        .args(&cmd[1..])
        .service_name(service_name)
        .slice(&slice)
        .collect_on_fail()
        .identity(systemd_run::Identity::dynamic())
        .runtime_max(lim.time)
        .timeout_stop(Duration::from_secs(0))
        .memory_max(lim.memory)
        .memory_swap_max(Byte::from_u64(0))
        .private_network()
        .private_ipc()
        .joins_namespace_of(ns)
        .mount("/", systemd_run::Mount::bind(u8p(&root)?))
        .mount("/tmp", tmp)
        .mount_api_vfs()
        .private_devices()
        .protect_proc(systemd_run::ProtectProc::invisible())
        .no_new_privileges()
        .limit_fsize(lim.output)
        .limit_nofile(etc.nofile_limit)
        .limit_stack(etc.stack_limit)
        .limit_core(Byte::from_u64(0))
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .current_dir("/tmp")
        .cpu_schedule(sched)
        .start()
        .await
        .map_err(Error::SystemdError)?
        .wait()
        .await
        .map_err(Error::SystemdError)
}

async fn judge<T: data::DataSource, P: AsRef<Path>, Q: AsRef<Path>>(
    cli: &Cli,
    etc: &ConfigFile,
    oj_data: &mut T,
    run_dir: P,
    tmp_dir: Q,
    old_verdict: &mut Option<Verdict>,
    max_time: &mut Duration,
) -> Result<Verdict> {
    use util::ensure_utf8_path as u8p;
    let d = oj_data.fetch(&cli.solution_id).await?;
    *old_verdict = d.old_result;

    let lang_cfg = etc.language.get(&d.language);
    if lang_cfg.is_none() {
        return Err(Error::UnconfiguredLanguage(d.language.clone()));
    }
    let lang_cfg = lang_cfg.unwrap();

    debug!("creating tmp directory {}", tmp_dir.as_ref().display());
    create_dir(&tmp_dir).map_err(Error::IOError)?;

    debug!("making tmp_dir global writable");
    use std::fs::{set_permissions, Permissions};
    use std::os::unix::fs::PermissionsExt;
    let perm = Permissions::from_mode(0o777);
    set_permissions(&tmp_dir, perm).map_err(Error::IOError)?;

    let src_path = tmp_dir.as_ref().join(&lang_cfg.src_name);
    debug!("saving source code to {}", src_path.display());
    {
        let mut src = File::create(src_path).map_err(Error::IOError)?;
        use std::io::Write;
        src.write_all(&d.source).map_err(Error::IOError)?;
    }

    let root = cli
        .cfg
        .chroot_dir
        .as_ref()
        .or(etc.config.chroot_dir.as_ref())
        .map(u8p)
        .transpose()?
        .unwrap_or("/");

    info!("compiling the source code");
    let cmd = lang_cfg.cmd_compile.clone();
    let lim = &etc.compiler_limit;
    let err = Some(run_dir.as_ref().join("ce.txt"));
    let compile_iospec = [None, None, err.as_ref()];
    let tmp_rw = (&tmp_dir, true);
    let tmp_ro = (&tmp_dir, false);
    let x = run(cli, etc, lim, cmd, root, tmp_rw, compile_iospec).await?;
    if x.is_failed() {
        info!("compilation failed");
        return Ok(Verdict::CompilerError);
    }

    let inp = run_dir.as_ref().join("input.txt");
    let refp = run_dir.as_ref().join("ref.txt");
    let outp = run_dir.as_ref().join("out.txt");
    let err = Some(run_dir.as_ref().join("re.txt"));
    let run_iospec = [Some(&inp), Some(&outp), err.as_ref()];

    let run_dir_u8 = u8p(&run_dir)?;
    let cmp_cmd = d
        .spj
        .as_ref()
        .map(|x| x.canonicalize())
        .transpose()
        .map_err(Error::IOError)?;

    let mut cmp_cmd = cmp_cmd.as_ref().map(u8p).transpose()?.map_or_else(
        || etc.default_cmp.clone(),
        |x| vec![x.to_owned(), "input.txt".to_owned()],
    );
    cmp_cmd.extend(["ref.txt".to_owned(), "out.txt".to_owned()]);
    let err = Some(run_dir.as_ref().join("cmp.txt"));
    let cmp_iospec = [None, err.as_ref(), None];

    let mut cnt = 0;
    *max_time = Duration::new(0, 0);
    for (tin, tout) in &d.testcases {
        cnt += 1;
        let test_name = tin
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("[bad filename]");
        info!("testing testcase {} ({})", cnt, test_name);

        use std::fs::copy;
        debug!("copying input for testcase {}", cnt);
        copy(tin, &inp).map_err(Error::IOError)?;
        debug!("copying reference output for testcase {}", cnt);
        let ref_size = copy(tout, &refp).map_err(Error::IOError)?;
        let cmd = lang_cfg.cmd_run.clone();
        let out_lim = Byte::from_u64(ref_size)
            .multiply(2)
            .and_then(|x| x.add(Byte::KIBIBYTE))
            .unwrap_or(Byte::MAX);

        let lim = RunLimit {
            time: d.time_limit,
            memory: d.memory_limit,
            output: out_lim.add(Byte::MEBIBYTE).unwrap_or(Byte::MAX),
            rt: true,
        };
        let x = run(cli, etc, &lim, cmd, root, tmp_ro, run_iospec).await?;

        let t = x.wall_time_usage();
        info!("{} seconds used for test {}", t.as_secs_f64(), cnt);

        if t > d.time_limit {
            *max_time = d.time_limit;
            return Ok(Verdict::TimeLimit);
        }
        *max_time = std::cmp::max(*max_time, x.wall_time_usage());

        let sz = std::fs::metadata(&outp).map_err(Error::IOError)?.len();

        if sz > out_lim.as_u64() {
            return Ok(Verdict::OutputLimit);
        }

        if x.is_failed() {
            return Ok(Verdict::RunError);
        }

        if sz == 0 {
            return Ok(Verdict::NoOutput);
        }

        let cmd = cmp_cmd.clone();
        let lim = &etc.compare_limit;
        let tmp_spec = (run_dir_u8, false);
        let x = run(cli, etc, lim, cmd, "/", tmp_spec, cmp_iospec).await?;
        if x.is_failed() {
            return Ok(Verdict::WrongAnswer);
        }
    }

    Ok(Verdict::Correct)
}

fn read_and_truncate_lossy<P: AsRef<Path>>(p: P, sz: usize) -> Result<String> {
    use std::io::Read;
    let mut buf = vec![0; sz + 1];
    let n = {
        let mut f = File::open(p).map_err(Error::IOError)?;
        f.read(&mut buf).map_err(Error::IOError)?
    };
    if n > sz {
        buf.resize(sz.saturating_sub(3), 0);
        buf.extend(b"...");
    }
    buf.resize(sz, 0);
    Ok(String::from_utf8_lossy(&buf).as_ref().to_owned())
}

async fn judge_feedback<T: data::DataSource, P: AsRef<Path>>(
    cli: &Cli,
    etc: &ConfigFile,
    oj_data: &mut T,
    run_dir: P,
) -> Result<()> {
    // Make run_dir absolute.
    create_dir_all(&run_dir).map_err(Error::IOError)?;
    let run_dir = run_dir.as_ref().canonicalize().map_err(Error::IOError)?;

    // Generate an "unique" name for tmp_dir.
    let mut tmp_dir = "opoj-".to_owned() + &cli.solution_id + "-";
    tmp_dir = tmp_dir + &uuid::Uuid::new_v4().simple().to_string();
    let tmp_dir = run_dir.join(tmp_dir);
    let mut old_verdict = None;
    let mut max_time = Duration::new(0, 0);

    let r = judge(
        cli,
        etc,
        oj_data,
        &run_dir,
        &tmp_dir,
        &mut old_verdict,
        &mut max_time,
    )
    .await;

    if std::fs::remove_dir_all(&tmp_dir).is_err() {
        error!("failed to remove directory {}", tmp_dir.display());
    }

    if let (Ok(v), Some(u)) = (&r, &old_verdict) {
        if v != u {
            warn!("verdict changed from {:?} to {:?}", u, v);
        }
    }
    if let Err(ref e) = r {
        error!("judgement failed: {}", e);
    }
    let r = r.unwrap_or(Verdict::JudgementFailed);
    info!("verdict = {:?}", r);

    if cli.cfg.dry.or(etc.config.dry) == Some(true) {
        return Ok(());
    }

    oj_data.feedback(&cli.solution_id, r, max_time).await?;

    // Compiler stderr
    let ce_path = run_dir.join("ce.txt");
    let ce_buf = read_and_truncate_lossy(ce_path, 32767)?
        .as_bytes()
        .to_owned();
    oj_data.feedback_ce(&cli.solution_id, ce_buf).await?;

    // Judge log and maybe compare output
    let log_path = run_dir.join("judge.log");
    let mut log_buf = read_and_truncate_lossy(log_path, 20000)?;

    if r == Verdict::WrongAnswer {
        let cmp_path = run_dir.join("cmp.txt");
        log_buf += "\nCompare Output:\n";
        let lim = 32767 - log_buf.len();
        log_buf += &read_and_truncate_lossy(cmp_path, lim)?;
    }

    let log_buf = log_buf.as_bytes().to_owned();
    oj_data.feedback_log(&cli.solution_id, log_buf).await?;

    Ok(())
}

#[async_std::main]
async fn main() {
    let cli = Cli::parse();
    let oj_base = &cli.oj_base;
    let runner_id = &cli.runner_id;

    let etc_path = cli
        .etc
        .clone()
        .unwrap_or_else(|| oj_base.join("etc/judge3.toml"));
    let etc = ConfigFile::load(&etc_path);

    // Without a configuration file, this program is useless because we
    // don't know how to compile or run anything.
    if let Err(e) = etc {
        panic!("config file {} is broken: {}", etc_path.display(), e);
    }

    let etc = etc.unwrap();

    // Change to working directory.
    let wd = cli.cfg.run_dir.as_ref().or(etc.config.run_dir.as_ref());
    if let Some(d) = wd {
        create_dir_all(d).unwrap();
        if std::env::set_current_dir(d).is_err() {
            panic!("cannot change to {}", d.display());
        }
    }

    // recreate our working directory under working directory
    let run_dir = PathBuf::from(format!("run{runner_id}"));
    create_dir_all(&run_dir).unwrap();

    let log_path = run_dir.join("judge.log");
    let log_file = File::create(&log_path)
        .expect("cannot create log file");
    let tee = io_tee::TeeWriter::new_stderr(log_file);

    env_logger::Builder::new()
        .filter(Some("judge_client_3"), log::LevelFilter::Info)
        .write_style(env_logger::WriteStyle::Always)
        .parse_default_env()
        .target(env_logger::Target::Pipe(Box::new(tee)))
        .init();

    // Real judging logic goes here.
    let ds = cli.cfg.data_source.or(etc.config.data_source);

    let r = match ds {
        None => {
            error!("data source is not specified");
            exit(1)
        }
        Some(DataSource::HustOJ) => {
            cfg_if! {
                if #[cfg(feature = "hustoj")] {
                    if etc.hust.db_url.is_empty() {
                        error!("connection URL is not set");
                        exit(1);
                    }
                    let db = data_hustoj::get(
                        &etc.hust.db_url,
                        &etc.hust.oj_home
                    ).await;
                    if let Err(e) = db {
                        error!("cannot connect to HustOJ DB: {}", e);
                        exit(1);
                    }
                    let mut db = db.unwrap();
                    judge_feedback(&cli, &etc, &mut db, &run_dir).await
                } else {
                    error!("HustOJ disabled at build time");
                    exit(1);
                }
            }
        }
        Some(DataSource::Mock) => {
            let mut oj_data = data_mock::MockDataSource::new();
            judge_feedback(&cli, &etc, &mut oj_data, &run_dir).await
        }
    };

    if let Err(e) = r {
        error!("error: {}", e);
        exit(1);
    }
}
