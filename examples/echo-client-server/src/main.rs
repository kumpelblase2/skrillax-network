use skrillax_packet::Packet;
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use skrillax_stream::stream::SilkroadTcpExt;
use tokio::net::TcpSocket;

#[derive(Serialize, Deserialize, ByteSize, Packet)]
#[packet(opcode = 0x01)]
struct ClientHello(String);

#[derive(Serialize, Deserialize, ByteSize, Packet)]
#[packet(opcode = 0x01)]
struct ServerHello(String);

#[tokio::main]
async fn main() {
    start_server();

    run_client().await;
}

fn start_server() {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:9998".parse().unwrap()).unwrap();
    let listener = socket.listen(1024).unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let (mut reader, mut writer) = client.into_silkroad_stream();
            let packet = reader.next_packet::<ClientHello>().await.unwrap();
            writer
                .send(ServerHello(format!("Hello {} from server :)", packet.0)))
                .await
                .unwrap();
        }
    });
}

async fn run_client() {
    let client = TcpSocket::new_v4().unwrap();
    let client = client
        .connect("127.0.0.1:9998".parse().unwrap())
        .await
        .unwrap();
    let (mut reader, mut writer) = client.into_silkroad_stream();
    writer
        .send(ClientHello(String::from("Test Client")))
        .await
        .unwrap();
    while let Ok(packet) = reader.next_packet::<ServerHello>().await {
        println!("Received from server: {}", packet.0);
    }
}
