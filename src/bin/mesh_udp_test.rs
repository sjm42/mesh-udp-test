// bin/tcp_server.rs

use std::{io, io::Write, net};

use clap::Parser;
use prost::Message;

// use tokio_util::{codec::BytesCodec, udp::UdpFramed};

use mesh_udp_test::*;

const MESH_MULTI: net::Ipv4Addr = net::Ipv4Addr::new(224, 0, 0, 69);
const BUFSZ: usize = 65536; // for XXL jumbo frames :)

fn main() -> anyhow::Result<()> {
    let opts = OptsCommon::parse();
    opts.start_pgm(env!("CARGO_BIN_NAME"));

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move { run_server(&opts).await })?;
    Ok(())
}

async fn run_server(opts: &OptsCommon) -> anyhow::Result<()> {
    let addr = &opts.listen;

    let sock = tokio::net::UdpSocket::bind(net::SocketAddrV4::new(MESH_MULTI, 4403)).await?;
    // sock.bind_device(Some("vlan0.14".as_bytes()))?;

    // sock.set_multicast_loop_v4(true)?;
    sock.join_multicast_v4(MESH_MULTI, net::Ipv4Addr::new(10, 28, 5, 10))?;
    // sock.join_multicast_v4(MESH_MULTI, net::Ipv4Addr::UNSPECIFIED)?;
    info!("Listening on {}", sock.local_addr()?);
    let mut buf = [0; BUFSZ];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        info!("Received {len} bytes from {addr}:\n{:02x?}", &buf[0..len]);

        // let res = protobufs::FromRadio::decode(&buf[..len]);
        let res = protobufs::MeshPacket::decode(&buf[..len]);
        info!("Decoded packet:\n{res:?}");
    }
    Ok(())
}

// EOF
