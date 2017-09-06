use std;
use std::io::{self, Write};
use std::net::TcpStream;

use r2d2::ManageConnection;

use errors::*;
use SERVERDATA_RESPONSE_VALUE;
use read_rcon_resp_multi;
use rcon_gen;
use StringError;
use RconConnection;
use connect;

pub struct OkManager {
    pub ip: String,
    pub port: u16,
    pub pw: String,
}

impl ManageConnection for OkManager {
    type Connection = RconConnection;
    type Error = StringError;

    fn connect(&self) -> std::result::Result<RconConnection, StringError> {
        match connect((self.ip.as_str(), self.port), &self.pw) {
            Ok(conn) => Ok(RconConnection {
                conn: conn,
                request_id: 10,
            }),
            Err(e) => {
                println!("error connect: {}", e);
                let mut stderr = io::stderr();
                for e in e.iter().skip(1) {
                    writeln!(stderr, "caused by: {}", e).expect("can't write to stderr");
                }

                if let Some(backtrace) = e.backtrace() {
                    writeln!(stderr, "backtrace: {:?}", backtrace).expect("can't write to stderr");
                }

                Err(StringError(e.to_string()))
            }
        }
    }

    fn is_valid(&self, conn: &mut RconConnection) -> std::result::Result<(), StringError> {
        let exec_id = conn.request_id;
        conn.request_id += 1;

        is_valid2(&mut conn.conn, exec_id).map_err(|e| StringError(format!("{:?}", e)))?;

        Ok(())
    }

    fn has_broken(&self, _: &mut RconConnection) -> bool {
        // TODO: desync == last sent id != last recv id?
        // https://docs.rs/r2d2_postgres/0.12.0/src/r2d2_postgres/lib.rs.html#1-130
        // conn.is_desynchronized()
        false
    }
}

fn is_valid2(mut conn: &mut TcpStream, exec_id: i32) -> Result<()> {
    let cmd_bin = rcon_gen(exec_id, "", SERVERDATA_RESPONSE_VALUE)?;
    conn.write_all(&cmd_bin)?;
    conn.take_error()?;

    let (reply, done) = read_rcon_resp_multi(&mut conn, exec_id)?;
    if reply.id != exec_id {
        bail!("id doesn't match");
    }
    if !done {
        bail!("malformed packet");
    }

    Ok(())
}
