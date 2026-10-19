//! Opening banner, styled the same way rustscan's is: a block-letter title
//! in a green gradient and a bordered info line in a yellow gradient, both
//! bold, via the same `colorful` crate rustscan itself uses for this. The
//! letterforms are a standard figlet font rather than rustscan's hand-drawn
//! one (that one's custom-built glyph by glyph for "RustScan" specifically,
//! and improvising new letters in it for "DUELSCAN" risked coming out
//! misaligned) - same color treatment, different typeface.

use colorful::{Color, Colorful};

const TITLE: &str = r#" ____  _   _ _____ _     ____   ____    _    _   _
|  _ \| | | | ____| |   / ___| / ___|  / \  | \ | |
| | | | | | |  _| | |   \___ \| |     / _ \ |  \| |
| |_| | |_| | |___| |___ ___) | |___ / ___ \| |\  |
|____/ \___/|_____|_____|____/ \____/_/   \_\_| \_|"#;

const INFO: &str = r#"________________________________________
: stateless SYN scanning, for the duel :
: v1.0 - @hacktivist1337 :
----------------------------------------"#;

/// Printed to stderr, like every other banner/diagnostic line this tool
/// emits - stdout stays reserved for `target:port` results only, so it's
/// always safe to pipe. Caller is responsible for skipping this in -silent
/// mode (same as every other banner).
pub fn print() {
    eprintln!("{}", TITLE.gradient(Color::Green).bold());
    eprintln!("{}", INFO.gradient(Color::Yellow).bold());
}
