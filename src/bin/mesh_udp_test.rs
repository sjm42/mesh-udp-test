// bin/tcp_server.rs

use std::net;

use clap::Parser;
use crypto::aes::{self, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;
use hex_literal::hex;
use pretty_hex::*;
use prost::Message;
use protobufs::{
    mesh_packet::{PayloadVariant, Priority}, Data, MeshPacket,
    PortNum,
};
use rand::prelude::*;

use mesh_udp_test::*;

const MESH_MULTI: net::Ipv4Addr = net::Ipv4Addr::new(224, 0, 0, 69);
const MESH_UDP_PORT: u16 = 4403;
const BUFSZ: usize = 65536; // for XXL jumbo frames :)

fn main() -> anyhow::Result<()> {
    let opts = OptsCommon::parse();
    opts.start_pgm(env!("CARGO_BIN_NAME"));

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move { run_server(&opts).await })?;
    Ok(())
}

async fn run_server(opts: &OptsCommon) -> anyhow::Result<()> {
    let mut rng = rand::rng();
    let interface_addr = opts.interface.parse()?;
    let multi_sockaddr = net::SocketAddrV4::new(MESH_MULTI, MESH_UDP_PORT);
    let tx_sockaddr = net::SocketAddrV4::new(interface_addr, MESH_UDP_PORT);

    let sock_rx = tokio::net::UdpSocket::bind(multi_sockaddr).await?;
    let sock_tx = tokio::net::UdpSocket::bind(tx_sockaddr).await?;
    // sock.set_multicast_loop_v4(true)?;
    sock_rx.join_multicast_v4(MESH_MULTI, interface_addr)?;
    info!(
        "Listening on {} ({})",
        sock_rx.local_addr()?,
        String::from_utf8_lossy(sock_rx.device()?.unwrap_or_default().as_slice())
    );

    let mut aes_iv: [u8; 16] = [0; 16];
    // don't ask (:facepalm:)
    let aes_key: [u8; 16] = hex!("d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01");

    let mut udp_rx_buf = [0; BUFSZ];
    loop {
        let (len, addr) = sock_rx.recv_from(&mut udp_rx_buf).await?;
        info!(
            "Received {len} bytes from {addr}:\n{:02x?}",
            &udp_rx_buf[0..len]
        );

        // attempting to decode mesh packet structure
        let rx_packet = match MeshPacket::decode(&udp_rx_buf[..len]) {
            Ok(packet) => packet,
            Err(e) => {
                error!("Packet decode error: {e:?}");
                continue;
            }
        };
        info!("Decoded packet:\n{rx_packet:?}");

        // outer structure of mesh packet was successfully parsed

        let enc_data = match rx_packet.payload_variant {
            Some(PayloadVariant::Encrypted(enc_data)) => enc_data,
            _ => continue,
        };

        // now we attempt to decrypt the payload
        let datalen = enc_data.len();
        info!("Attempting to decrypt {datalen} bytes");
        info!("Encrypted payload:\n{:?}", enc_data.hex_dump());

        aes_iv.fill(0);
        aes_iv[0..4].copy_from_slice(&rx_packet.id.to_le_bytes());
        aes_iv[8..12].copy_from_slice(&rx_packet.from.to_le_bytes());
        let mut cipher = aes::ctr(KeySize::KeySize128, &aes_key, &aes_iv);
        let mut outbuf = vec![0; datalen];
        cipher.process(&enc_data, &mut outbuf);
        info!("Decrypted payload:\n{:?}", outbuf.hex_dump());

        // attempting to decode the inner payload that was supposedly decrypted
        let rx_data = match Data::decode(outbuf.as_slice()) {
            Ok(rx_data) => rx_data,
            Err(e) => {
                error!("Payload decode error: {e:?}");
                continue;
            }
        };
        info!("Decoded payload:\n{rx_data:?}");

        match rx_data.portnum.try_into() {
            Ok(PortNum::TextMessageApp) => {
                let msg = String::from_utf8_lossy(&rx_data.payload);
                info!("Got MSG: \"{msg}\"");

                if msg != "Pim" {
                    info!("Not sending a response");
                    continue;
                }

                let tx_data = Data {
                    portnum: PortNum::TextMessageApp as i32,
                    payload: "Pom".as_bytes().to_vec(),
                    ..Default::default()
                };

                // Create the payload variant
                let tx_packet = MeshPacket {
                    channel: 0,
                    transport_mechanism: rx_packet.transport_mechanism,
                    from: 0x4242_4242, // Just a made up nodeid :)
                    to: rx_packet.from, // do not send reply as broadcast but DM instead
                    id: rng.random_range(65536..u32::MAX),
                    priority: Priority::Default as i32,
                    hop_limit: 5,
                    payload_variant: Some(PayloadVariant::Decoded(tx_data)),
                    ..Default::default()
                };

                let udp_packet = tx_packet.encode_to_vec();
                info!("Sending response:\n{:?}", udp_packet.hex_dump());
                let n_sent = sock_tx.send_to(&udp_packet, multi_sockaddr).await?;
                info!("Sent {n_sent} bytes.");
            }
            Ok(PortNum::NodeinfoApp) => {
                let info = String::from_utf8_lossy(&rx_data.payload);
                info!("Got Nodeinfo:\n{info}");
                let nodeinfo =
                    protobufs::User::decode(rx_data.payload.as_slice()).unwrap_or_default();
                info!("Parsed Nodeinfo:\n{nodeinfo:?}");
            }
            Ok(PortNum::PositionApp) => {
                info!("Got Position");
                let pos =
                    protobufs::Position::decode(rx_data.payload.as_slice()).unwrap_or_default();
                info!("Parsed Position:\n{pos:?}");
            }
            Ok(PortNum::RoutingApp) => {
                info!("Got Routing message");
                let routing =
                    protobufs::Routing::decode(rx_data.payload.as_slice()).unwrap_or_default();
                info!("Parsed Routing:\n{routing:?}");
            }

            _ => {}
        }
    }

    // not reached :)
    // Ok(())
}
// EOF
