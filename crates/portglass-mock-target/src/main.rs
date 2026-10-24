use clap::Parser;

/// Mock embedded-device web interface for testing PortGlass. Never expose it to a network.
#[derive(Parser)]
#[command(name = "portglass-mock-target", version)]
struct Cli {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:18080")]
    listen: String,
    /// Serve HTTPS with a throwaway self-signed certificate.
    #[arg(long)]
    https: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let cli = Cli::parse();
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    let addr = listener.local_addr()?;
    if cli.https {
        let acceptor =
            portglass_mock_target::https_acceptor(vec!["localhost".into(), addr.ip().to_string()])?;
        println!("Mock device (HTTPS, self-signed) on https://{addr}/");
        portglass_mock_target::serve_https(listener, acceptor).await?;
    } else {
        println!("Mock device on http://{addr}/");
        portglass_mock_target::serve_http(listener).await?;
    }
    Ok(())
}
