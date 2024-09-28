use chrono::{DateTime, Utc};
use skrillax_packet::Packet;
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use skrillax_stream::{handshake::PassiveSecuritySetup, stream::SilkroadTcpExt};
use std::net::ToSocketAddrs;
use tokio::net::{TcpSocket, TcpStream};

const JOYMAX_GATEWAY_ADDRESS: &str = "gwgt1.joymax.com:15779";

#[derive(Packet, ByteSize, Serialize, Deserialize)]
#[packet(opcode = 0x2001)]
pub struct IdentityInformation {
    pub module_name: String,
    pub locality: u8,
}

#[derive(Clone, Deserialize, Serialize, ByteSize, Packet, Debug)]
#[packet(opcode = 0x6104)]
pub struct GatewayNoticeRequest {
    pub unknown: u8,
}

#[derive(Clone, Serialize, Deserialize, ByteSize, Packet, Debug)]
#[packet(opcode = 0xA104, massive = true)]
pub struct GatewayNoticeResponse {
    #[silkroad(list_type = "length")]
    pub notices: Vec<GatewayNotice>,
}

type ServerDateTime = DateTime<Utc>;

#[derive(Clone, Deserialize, Serialize, ByteSize, Debug)]
pub struct GatewayNotice {
    #[silkroad(size = 2)]
    pub subject: String,
    #[silkroad(size = 2)]
    pub article: String,
    pub published: ServerDateTime,
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
    writer
        .write_packet(GatewayNoticeRequest { unknown: 0x12 })
        .await
        .unwrap();
    let notices = reader.next_packet::<GatewayNoticeResponse>().await.unwrap();
    for notice in notices.notices {
        println!(
            "{}: {} - {}",
            notice.published,
            notice.subject,
            &notice.article[0..10]
        );
    }
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
