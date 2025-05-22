//! Provides convenient abstractions for handling streams of Silkroad Online
//! packets.
//!
//! While it is possible to simply use the abstractions provided by more lover
//! level crates of the stack, such as simply using [skrillax_packet] and
//! [skrillax_codec], it can become quite cumbersome. In particular, when
//! dealing with lots of different packets it might be easier to create logical
//! groupings of packets: protocols.
//!
//! Protocols are essentially just a collection of packets and possibly other
//! protocols that allow reading and writing a single type instead of handling
//! all possible cases manually.
//!
//! It is expected that you'll be using a [tokio::net::TcpStream] for the
//! connection such that you can create a Silkroad stream from by calling
//! [stream::SilkroadTcpExt::into_silkroad_stream]. With the resulting
//! [stream::SilkroadStreamRead] and [stream::SilkroadStreamWrite], you can now
//! read packets using [stream::SilkroadStreamRead::next_packet]
//! and write packets using [stream::SilkroadStreamWrite::write_packet].
//!
//! On top of the provided stream abstraction, this provides a way to handle the
//! security handshake through [handshake::ActiveSecuritySetup] and
//! [handshake::PassiveSecuritySetup] for the server point of view and the
//! client respectively.

pub mod handshake;
pub mod stream;

pub mod packet {
    pub use skrillax_packet::*;
}
pub use stream::InputProtocol;
pub use stream::OutputProtocol;
