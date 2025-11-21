# mesh-udp-test
Parsing Meshtastic packets sent via udp multicast

## example session

```
root@ap1:~# ./mesh_udp_test -d -i 10.x.y.z
2025-11-21T21:23:05.977441Z  INFO Starting up mesh_udp_test v0.0.2...
2025-11-21T21:23:05.977531Z DEBUG Git branch: master
2025-11-21T21:23:05.977546Z DEBUG Git commit: d417cf4aa77720a7d99853c32a5cad5d45cbc32c
2025-11-21T21:23:05.977556Z DEBUG Source timestamp: 2025-11-21T14:31:28Z
2025-11-21T21:23:05.977565Z DEBUG Compiler version: rustc 1.91.1 (ed61e7d7e 2025-11-07)
2025-11-21T21:23:05.978487Z  INFO Listening on 224.0.0.69:4403 ()
...
2025-11-21T21:26:40.523898Z  INFO Received 60 bytes from 10.28.5.21:4403:
[0d, 08, 8d, d1, 69, 15, ff, ff, ff, ff, 18, 55, 2a, 0a, c5, 53, 45, d9, 5e, 2f, 26, 44, 77, 81, 35, 7b, ca, 81, 91, 3d, 10, d9, 20, 69, 45, 00, 00, 40, 41, 48, 04, 58, 64, 60, d4, ff, ff, ff, ff, ff, ff, ff, ff, 01, 78, 05, 98, 01, c8, 01]
2025-11-21T21:26:40.523978Z  INFO Decoded packet:
MeshPacket { from: 1775340808, to: 4294967295, channel: 85, id: 2441202299, rx_time: 1763760400, rx_snr: 12.0, hop_limit: 4, want_ack: false, priority: High, rx_rssi: -44, delayed: NoDelay, via_mqtt: false, hop_start: 5, public_key: [], pki_encrypted: false, next_hop: 0, relay_node: 200, tx_after: 0, transport_mechanism: TransportInternal, payload_variant: Some(Encrypted([197, 83, 69, 217, 94, 47, 38, 68, 119, 129])) }
2025-11-21T21:26:40.524023Z  INFO Attempting to decrypt 10 bytes
2025-11-21T21:26:40.524033Z  INFO Encrypted payload:
Length: 10 (0xa) bytes
0000:   c5 53 45 d9  5e 2f 26 44  77 81                      .SE.^/&Dw.
2025-11-21T21:26:40.524149Z  INFO Decrypted payload:
Length: 10 (0xa) bytes
0000:   08 01 12 04  50 69 6e 67  48 00                      ....PingH.
2025-11-21T21:26:40.524174Z  INFO Decoded payload:
Data { portnum: TextMessageApp, payload: [80, 105, 110, 103], want_response: false, dest: 0, source: 0, request_id: 0, reply_id: 0, emoji: 0, bitfield: Some(0) }
2025-11-21T21:26:40.524193Z  INFO Got MSG: "Ping"

```


## extra tricks

Cross-build for Asus RT-AX59U with arm64 cpu running OpenWrt

```
cross build --release --target aarch64-unknown-linux-musl
```

Cross-build for Asus RT-AX53U with mips cpu running OpenWrt

```
cross +nightly build -Z build-std --release --target mipsel-unknown-linux-musl
```
