use std;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};

use r2d2::ManageConnection;

use Error;
use SERVERDATA_RESPONSE_VALUE;
use read_rcon_resp_multi;
use rcon_gen;
use StringError;
use RconConnection;
use connect;

#[derive(Debug)]
pub struct RconManager {
    pub ip: String,
    pub port: u16,
    pub pw: String,
}

impl ManageConnection for RconManager {
    type Connection = RconConnection;
    type Error = StringError;

    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let ip: std::net::IpAddr = self.ip
            .parse()
            .map_err(|e: std::net::AddrParseError| StringError(e.to_string()))?;
        let addr = SocketAddr::new(ip, self.port);

        match connect(&addr, &self.pw) {
            Ok(conn) => Ok(RconConnection {
                conn: conn,
                request_id: 10,
            }),
            Err(e) => {
                println!("error connect: {}", e);
                for cause in e.causes() {
                    println!("{}", cause);
                }

                Err(StringError(e.to_string()))
            }
        }
    }

    fn is_valid(&self, conn: &mut RconConnection) -> std::result::Result<(), Self::Error> {
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

fn is_valid2(mut conn: &mut TcpStream, exec_id: i32) -> Result<(), Error> {
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
