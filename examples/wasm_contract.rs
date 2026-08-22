//! Exact shared contract suite executed as a real WASI program.

#[path = "../tests/support/component_contract.rs"]
mod component_contract;

fn main() {
    component_contract::run();
}
