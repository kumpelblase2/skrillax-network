use std::net::ToSocketAddrs;

use skrillax_packet::Packet;
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use skrillax_stream::{handshake::PassiveSecuritySetup, stream::SilkroadTcpExt};
use tokio::net::{TcpSocket, TcpStream};

const JOYMAX_GATEWAY_ADDRESS: &str = "gwgt1.joymax.com:15779";

#[derive(Packet, ByteSize, Serialize, Deserialize)]
#[packet(opcode = 0x2001)]
pub struct IdentityInformation {
    pub module_name: String,
    pub locality: u8,
}

#[tokio::main]
async fn main() {
    let connection = connect_to_silkroad().await;
    let (mut reader, mut writer) = connection.into_silkroad_stream();
    PassiveSecuritySetup::handle(&mut reader, &mut writer)
        .await
        .unwrap();
    writer
        .write_packet(IdentityInformation {
            module_name: "SR_Client".to_owned(),
            locality: 0,
        })
        .await
        .unwrap();

    let their_info = reader.next_packet::<IdentityInformation>().await.unwrap();
    println!("{}", their_info.module_name);
}

async fn connect_to_silkroad() -> TcpStream {
    let domain = JOYMAX_GATEWAY_ADDRESS
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let socket = TcpSocket::new_v4().unwrap();
    socket.connect(domain).await.unwrap()
}
