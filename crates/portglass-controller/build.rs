fn main() {
    println!("cargo:rerun-if-changed=src/ui/index.html");
    // Visible identity in Explorer > Properties > Details, for administrators and EDR review.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("FileDescription", "PortGlass Controller")
            .set("ProductName", "PortGlass")
            .set("CompanyName", "Joseph Spillers")
            .set(
                "LegalCopyright",
                "Copyright (c) 2026 Joseph Spillers. MIT License.",
            )
            .set("OriginalFilename", "portglass.exe")
            .set("InternalName", "portglass");
        if let Err(e) = res.compile() {
            println!("cargo:warning=version resource not embedded: {e}");
        }
    }
}
