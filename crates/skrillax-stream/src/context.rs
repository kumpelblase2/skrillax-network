#![allow(unused)] // these are only used in macros so they are 'unused'
use skrillax_serde::SerdeContext;

#[derive(Copy, Clone, Default)]
pub struct LastSentPacket(pub u16);

pub fn last_sent_packet_is(ctx: &SerdeContext, expected_opcode: u16) -> bool {
    ctx.get::<LastSentPacket>().unwrap_or_default().0 == expected_opcode
}

#[derive(Copy, Clone, Default)]
pub struct LastReceivedPacket(pub u16);

pub fn last_received_packet_is(ctx: &SerdeContext, expected_opcode: u16) -> bool {
    ctx.get::<LastReceivedPacket>().unwrap_or_default().0 == expected_opcode
}
