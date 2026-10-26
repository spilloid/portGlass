fn main() {
    // Visible identity in Explorer > Properties > Details, for administrators and EDR review.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("FileDescription", "PortGlass Relay")
            .set("ProductName", "PortGlass")
            .set("CompanyName", "Joseph Spillers")
            .set(
                "LegalCopyright",
                "Copyright (c) 2026 Joseph Spillers. MIT License.",
            )
            .set("OriginalFilename", "portglass-relay.exe")
            .set("InternalName", "portglass-relay");
        if let Err(e) = res.compile() {
            println!("cargo:warning=version resource not embedded: {e}");
        }
    }
}
