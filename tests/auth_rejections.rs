#[path = "support/auth_rejections.rs"]
mod auth_rejections;

#[test]
fn auth_http_rejections_have_direct_and_brokered_parity() {
    auth_rejections::run();
}
