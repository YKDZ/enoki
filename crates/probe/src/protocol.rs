pub mod enoki {
    pub mod v1 {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packages/proto/src/generated/rust/enoki.v1.rs"
        ));
    }
}
