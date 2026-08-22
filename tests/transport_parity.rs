#[path = "support/component_contract.rs"]
mod component_contract;

#[test]
fn native_transport_runs_the_component_contract() {
    component_contract::run();
}
