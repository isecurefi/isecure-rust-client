//! Focused auth rejection parity executed as a real WASI program.
#[path = "../tests/support/auth_rejections.rs"]
mod auth_rejections;

fn main() {
    auth_rejections::run();
}
