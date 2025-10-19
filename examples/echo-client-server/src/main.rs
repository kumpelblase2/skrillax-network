use skrillax_packet::Packet;
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use skrillax_stream::handshake::{ActiveSecuritySetup, PassiveSecuritySetup, StaticRegistryExt};
use skrillax_stream::registry::PacketRegistry;
use skrillax_stream::stream::SilkroadTcpExt;
use tokio::net::TcpSocket;

#[derive(Serialize, Deserialize, ByteSize, Packet)]
#[packet(opcode = 0x01, encrypted = true)]
struct ClientHello(String);

#[derive(Serialize, Deserialize, ByteSize, Packet)]
#[packet(opcode = 0x01, encrypted = true)]
struct ServerHello(String);

#[tokio::main]
async fn main() {
    start_server();
    run_client().await;
}

fn start_server() {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:9999".parse().unwrap()).unwrap();
    let listener = socket.listen(5).unwrap();
    tokio::spawn(async move {
        let (client, _) = listener
            .accept()
            .await
            .expect("Should be able to accept client.");
        let server_registry = PacketRegistry::builder()
            .register_active_handshake()
            .register_incoming::<ClientHello>()
            .register_outgoing::<ServerHello>()
            .build();
        let (mut reader, mut writer) = client.into_silkroad_stream(server_registry);
        ActiveSecuritySetup::handle(&mut reader, &mut writer)
            .await
            .expect("Security setup should be handled.");
        let received_packet = reader.next_packet().await.unwrap();
        let packet = received_packet.into_packet::<ClientHello>().unwrap();
        writer
            .write_packet(ServerHello(format!("Hello {} from server :)", packet.0)))
            .await
            .unwrap();
    });
}

async fn run_client() {
    let client = TcpSocket::new_v4().unwrap();
    let client = client
        .connect("127.0.0.1:9999".parse().unwrap())
        .await
        .unwrap();
    let client_registry = PacketRegistry::builder()
        .register_passive_handshake()
        .register_outgoing::<ClientHello>()
        .register_incoming::<ServerHello>()
        .build();
    let (mut reader, mut writer) = client.into_silkroad_stream(client_registry);
    PassiveSecuritySetup::handle(&mut reader, &mut writer)
        .await
        .expect("Security setup should be handled.");
    writer
        .write_packet(ClientHello(String::from("Test Client")))
        .await
        .unwrap();
    let received_packet = reader
        .next_packet()
        .await
        .expect("Should receive the hello.");
    let packet = received_packet.into_packet::<ServerHello>().unwrap();
    println!("Received from server: {}", packet.0);
}
