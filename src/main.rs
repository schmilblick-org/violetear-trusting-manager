use std::env;
use std::io::Write;

use clam_client::response::ClamScanResult;
use clam_client::response::ClamScanResult::{Error, Found};
use clap::{App, Arg};
use fallible_iterator::FallibleIterator;
use postgres::types::ToSql;
use r2d2::Pool;
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use tempfile::tempfile_in;

fn main() {
    let args = App::new("Violetear Trusting Manager")
        .arg(
            Arg::with_name("clamav")
                .takes_value(false)
                .long("clamav")
                .short("cl"),
        )
        .get_matches();

    let db_url = env::var("DATABASE_URL").expect("incomplete database configuration");
    let pool = Pool::new(PostgresConnectionManager::new(db_url, TlsMode::None).unwrap())
        .expect("connecting to database failed");

    let mut clamav_enabled = args.is_present("clamav");
    let clamd_host = env::var("CLAMD_HOST");
    let clamd_port = env::var("CLAMD_PORT");

    if clamav_enabled {
        if clamd_host.is_err() || clamd_port.is_err() {
            eprintln!("CLAMD_HOST and CLAMD_PORT environment variables must be defined.");
            clamav_enabled = false;
        }
    }

    let clamd_host = clamd_host.unwrap_or_else(|_| "".into());
    let clamd_port = clamd_port.unwrap_or_else(|_| "0".into());
    let clamd_port = clamd_port.parse().unwrap();

    let conn = pool.get().unwrap();

    conn.query("LISTEN tasks_created", &[]).unwrap();

    let notifications = conn.notifications();
    let mut blocking_iter = notifications.blocking_iter();

    let clamav_profile_id: i64 = conn
        .query(
            "SELECT id FROM profiles WHERE machine_name = $1",
            &[&"clamav_daemon"],
        )
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .get(0);

    loop {
        let x = blocking_iter.next().unwrap().unwrap();

        match x.channel.as_str() {
            "tasks_created" => {
                println!("Received tasks_created notification.");

                if clamav_enabled {
                    let conn = pool.get().unwrap();

                    conn.query("BEGIN", &[]).unwrap();

                    let stmt = conn.prepare("SELECT id, report_id FROM tasks WHERE profile_id = $1 AND status = $2 FOR UPDATE SKIP LOCKED").unwrap();
                    let rows = stmt.query(&[&clamav_profile_id, &"new"]).unwrap();

                    let tpool = ThreadPoolBuilder::new()
                        .num_threads(rows.len())
                        .build()
                        .unwrap();
                    let (tx, rx) = std::sync::mpsc::channel();

                    for row in &rows {
                        let task_id: i64 = row.get(0);
                        let report_id: i64 = row.get(1);

                        for row in &conn
                            .query("SELECT file FROM reports WHERE id = $1", &[&report_id])
                            .unwrap()
                        {
                            let file: Option<Vec<u8>> = row.get(0);

                            if let Some(file) = file {
                                let clamd_host = clamd_host.clone();
                                let tx = tx.clone();
                                tpool.spawn(move || {
                                    let clam = clam_client::client::ClamClient::new_with_timeout(
                                        &clamd_host,
                                        clamd_port,
                                        15,
                                    );

                                    if let Ok(clam) = clam {
                                        let mut tmp = tempfile::NamedTempFile::new().unwrap();

                                        tmp.write_all(&file).unwrap();

                                        println!("Processing task {}..", task_id);
                                        if let Ok(result) =
                                            clam.scan_path(tmp.path().to_str().unwrap(), false)
                                        {
                                            tx.send((task_id, result));
                                        }
                                    }
                                });
                            }
                        }
                    }

                    std::mem::drop(tpool);
                    std::mem::drop(tx);

                    for (task_id, result) in rx {
                        for result in result {
                            println!("Processed task {} successfully.", task_id);
                            match result {
                                ClamScanResult::Found(_, detection) => {
                                    conn.execute(
                                        "UPDATE tasks SET status = $1, message = $2 WHERE id = $3",
                                        &[&"detected", &detection, &task_id],
                                    );
                                }
                                ClamScanResult::Ok => {
                                    conn.execute(
                                        "UPDATE tasks SET status = $1, message = $2 WHERE id = $3",
                                        &[&"clean", &"", &task_id],
                                    );
                                }
                                ClamScanResult::Error(e) => {
                                    conn.execute(
                                        "UPDATE tasks SET status = $1, message = $2 WHERE id = $3",
                                        &[&"error", &format!("{:?}", e), &task_id],
                                    );
                                }
                            }
                        }
                    }

                    conn.query("COMMIT", &[]).unwrap();
                }
            }
            _ => {}
        };
    }
}
