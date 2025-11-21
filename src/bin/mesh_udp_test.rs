// bin/tcp_server.rs

use std::net;

use clap::Parser;
use crypto::aes::{self, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;
use hex_literal::hex;
use pretty_hex::*;
use prost::Message;
use protobufs::{mesh_packet::PayloadVariant, MeshPacket, PortNum};

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
    let sock = tokio::net::UdpSocket::bind(net::SocketAddrV4::new(MESH_MULTI, 4403)).await?;
    // sock.set_multicast_loop_v4(true)?;
    sock.join_multicast_v4(MESH_MULTI, opts.interface.parse()?)?;
    info!(
        "Listening on {} ({})",
        sock.local_addr()?,
        String::from_utf8_lossy(sock.device()?.unwrap_or_default().as_slice())
    );

    let mut aes_iv: [u8; 16] = [0; 16];
    // don't ask (:facepalm:)
    let aes_key: [u8; 16] = hex!("d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01");

    let mut udp_buf = [0; BUFSZ];
    loop {
        let (len, addr) = sock.recv_from(&mut udp_buf).await?;
        info!(
            "Received {len} bytes from {addr}:\n{:02x?}",
            &udp_buf[0..len]
        );

        // attempting to decode mesh packet structure
        let meshpacket = match MeshPacket::decode(&udp_buf[..len]) {
            Err(e) => {
                error!("Packet decode error: {e:?}");
                continue;
            }
            Ok(packet) => packet,
        };
        info!("Decoded packet:\n{meshpacket:?}");

        // outer structure of mesh packet was successfully parsed

        if let Some(PayloadVariant::Encrypted(enc_data)) = meshpacket.payload_variant {
            // now we attempt to decrypt the payload

            let datalen = enc_data.len();
            info!("Attempting to decrypt {datalen} bytes");
            info!("Encrypted payload:\n{:?}", enc_data.hex_dump());

            aes_iv.fill(0);
            aes_iv[0..4].copy_from_slice(&meshpacket.id.to_le_bytes());
            aes_iv[8..12].copy_from_slice(&meshpacket.from.to_le_bytes());
            let mut cipher = aes::ctr(KeySize::KeySize128, &aes_key, &aes_iv);
            let mut outbuf = vec![0; datalen];
            cipher.process(&enc_data, &mut outbuf);
            info!("Decrypted payload:\n{:?}", outbuf.hex_dump());

            // attempting to decode the inner payload that was supposedly decrypted
            let rx_data = match protobufs::Data::decode(outbuf.as_slice()) {
                Err(e) => {
                    error!("Payload decode error: {e:?}");
                    continue;
                }
                Ok(rx_data) => rx_data,
            };
            info!("Decoded payload:\n{rx_data:?}");

            if rx_data.portnum == PortNum::TextMessageApp as i32 {
                let msg = String::from_utf8_lossy(&rx_data.payload);
                info!("Got MSG: \"{msg}\"");
            }
        }
    }

    // not reached :)
    // Ok(())
}
// EOF
