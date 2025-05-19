use std::fmt::Display;

pub(crate) struct Opcode(pub(crate) u16);

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}
