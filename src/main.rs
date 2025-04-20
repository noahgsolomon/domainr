use clap::{Parser, Subcommand};
use rcgen::{CertificateParams, IsCa, BasicConstraints, KeyPair};
use std::{env, fs, path::PathBuf, process::Command, io::Write, collections::HashMap};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, Stdio};
use std::time::Duration;
use std::thread;
use std::io::{self, Read};
use std::sync::Arc;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::str::FromStr;
use rustls::{Certificate as RustlsCertificate, PrivateKey};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::Stream;
use rustls::sign::any_supported_type;
use rcgen::{CertificateParams as RcgenParams, Certificate as RcgenCert, DnType, SanType, KeyPair as RcgenKeyPair};
use std::sync::Arc as StdArc; // avoid conflict with super::Arc

#[derive(Parser)]
#[command(name = "domainr", version, about = "CLI for custom domain remapping")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Remap an upstream domain to an alias
    Remap {
        /// The real upstream domain (e.g., x.com)
        upstream: String,
        /// The alias domain (e.g., a.a)
        alias: String,
    },
    /// List all existing domain remappings
    List,
    /// Remove a remapping by alias domain
    Remove {
        /// The alias domain to remove (e.g., a.a)
        alias: String,
    },
    /// Generate a root CA and install it in the system trust store
    Init,
    /// Run the DNS server
    RunDnsServer,
    /// Run the HTTPS proxy server (hidden command)
    RunHttpsProxy,
}

// Structure to store domain mappings
#[derive(Debug, Serialize, Deserialize)]
struct Mappings {
    domains: HashMap<String, String>, // alias -> upstream
}

impl Mappings {
    fn new() -> Self {
        Mappings {
            domains: HashMap::new(),
        }
    }
}

fn get_config_dir() -> Result<PathBuf> {
    let mut config_dir = PathBuf::from(env::var("HOME")?);
    config_dir.push(".domainr");
    fs::create_dir_all(&config_dir)?;
    Ok(config_dir)
}

fn save_mapping(upstream: &str, alias: &str) -> Result<()> {
    let config_dir = get_config_dir()?;
    let mappings_path = config_dir.join("mappings.json");
    
    // Load existing mappings or create new ones
    let mut mappings = if mappings_path.exists() {
        let content = fs::read_to_string(&mappings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| Mappings::new())
    } else {
        Mappings::new()
    };
    
    // Add/update mapping
    mappings.domains.insert(alias.to_string(), upstream.to_string());
    
    // Save updated mappings
    let json = serde_json::to_string_pretty(&mappings)?;
    fs::write(mappings_path, json)?;
    
    println!("Saved mapping: {} -> {}", alias, upstream);
    Ok(())
}

fn init() -> Result<()> {
    // 1) Make ~/.domainr and define where to store the CA
    let mut ca_dir = PathBuf::from(env::var("HOME")?);
    ca_dir.push(".domainr");
    fs::create_dir_all(&ca_dir)?;
    let ca_cert_path = ca_dir.join("ca.pem");
    let ca_key_path  = ca_dir.join("ca-key.pem");

    // 2) Generate a self‑signed root CA if it doesn't already exist
    if !ca_cert_path.exists() {
        // Generate a new key pair for our CA
        let key_pair = KeyPair::generate()?;
        
        // Create CA certificate parameters
        let mut params = CertificateParams::new(vec![])?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        
        // Set the proper distinguished name
        params.distinguished_name.push(rcgen::DnType::CommonName, "domainr-root-ca");
        
        // Build the root CA certificate
        let ca = params.self_signed(&key_pair)?;
        fs::write(&ca_cert_path, ca.pem())?;
        fs::write(&ca_key_path, key_pair.serialize_pem())?;
        println!("Generated root CA in {}", ca_dir.display());
    } else {
        println!("Found existing CA in {}", ca_dir.display());
    }

    // 3) Install it into the macOS System keychain (requires sudo)
    //    This will prompt for your password if you haven't already run
    //    the binary via `sudo`.
    let status = Command::new("sudo")
        .args(&[
            "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            ca_cert_path.to_str().unwrap(),
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to install CA into system trust store");
    }
    println!("Installed CA into System keychain");

    // 4) (Optionally) flush the DNS cache so any /etc/resolver changes take effect:
    Command::new("sudo")
        .args(&["dscacheutil", "-flushcache"])
        .status()?;
    Command::new("sudo")
        .args(&["killall", "-HUP", "mDNSResponder"])
        .status()?;
    println!("Flushed DNS cache");

    Ok(())
}

fn remap(upstream: &str, alias: &str) -> Result<()> {
    // 1. First, store this mapping in your config
    save_mapping(upstream, alias)?;
    
    // 2. Create /etc/resolver/{alias} and /etc/resolver/{upstream}
    write_resolver_file(alias)?;
    write_resolver_file(upstream)?;
    
    // 3. Flush DNS cache so changes take effect
    flush_dns_cache()?;
    
    // 4. Generate on-the-fly leaf certificates for both domains
    // (this would happen in your proxy when a connection comes in)
    
    // 5. Start/restart your DNS stub and HTTPS proxy if not running
    ensure_daemons_running()?;
    
    Ok(())
}

fn write_resolver_file(domain: &str) -> Result<()> {
    // Need sudo to write to /etc/resolver
    let content = format!(
        "# Created by domainr\n\
         nameserver 127.0.0.1\n\
         nameserver 8.8.8.8  # fallback\n\
         port 53\n\
         timeout 1\n"
    );
    
    Command::new("sudo")
        .args(&[
            "tee", &format!("/etc/resolver/{}", domain)
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()?
        .stdin
        .unwrap()
        .write_all(content.as_bytes())?;
    
    Ok(())
}

// Implement the remaining missing functions as stubs for now
fn flush_dns_cache() -> Result<()> {
    Command::new("sudo")
        .args(&["dscacheutil", "-flushcache"])
        .status()?;
    Command::new("sudo")
        .args(&["killall", "-HUP", "mDNSResponder"])
        .status()?;
    println!("Flushed DNS cache");
    Ok(())
}

// Load all domain mappings from the config file
fn load_mappings() -> Result<Mappings> {
    let config_dir = get_config_dir()?;
    let mappings_path = config_dir.join("mappings.json");
    
    if mappings_path.exists() {
        let content = fs::read_to_string(&mappings_path)?;
        serde_json::from_str(&content).context("Failed to parse mappings file")
    } else {
        Ok(Mappings::new())
    }
}

// DNS server module - simplify using direct UDP
mod dns_server {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Duration;
    
    // Start the DNS server as a child process
    pub fn start_dns_server() -> Result<Child> {
        // Start the DNS server as a separate process
        let dns_server = Command::new("sudo")
            .args(&[
                env::current_exe()?.to_str().unwrap(),
                "run-dns-server"
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start DNS server process")?;

        // Wait a moment for the server to start
        thread::sleep(Duration::from_millis(500));
        
        // TODO: Check if the server is actually running
        
        Ok(dns_server)
    }
    
    // This will be called by our "run-dns-server" command
    pub fn run_server() -> Result<()> {
        println!("Starting DNS server on 127.0.0.1:53...");
        
        // Load our domain mappings
        let mappings = load_mappings()?;
        
        // Create a UDP socket bound to localhost port 53
        let socket = UdpSocket::bind("127.0.0.1:53")?;
        
        let mut buf = [0; 512]; // Standard DNS packet size
        
        println!("DNS server listening...");
        
        loop {
            // Wait for a DNS query
            match socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    // Parse the incoming DNS query
                    if let Ok(query) = Message::from_vec(&buf[..size]) {
                        // Create a response message
                        let mut response = Message::new();
                        response.set_id(query.id())
                             .set_message_type(MessageType::Response)
                             .set_op_code(OpCode::Query)
                             .set_recursion_desired(query.recursion_desired())
                             .set_recursion_available(true)
                             .add_queries(query.queries().to_vec());
                        
                        // Check if this is a standard query
                        if query.message_type() == MessageType::Query && query.op_code() == OpCode::Query {
                            // Handle each question
                            for question in query.queries() {
                                // Extract the domain name and convert to string
                                let domain = question.name().to_string();
                                let domain = domain.trim_end_matches('.');
                                println!("DNS query for: {}", domain);
                                
                                // Check if this is an A record query (IPv4 address)
                                if question.query_class() == DNSClass::IN && question.query_type() == RecordType::A {
                                    // Check if this domain is in our mappings
                                    let is_mapped = mappings.domains.contains_key(domain) || 
                                                   mappings.domains.values().any(|v| v == domain);
                                    
                                    if is_mapped {
                                        println!("Domain {} is mapped, returning 127.0.0.1", domain);
                                        
                                        // Create a record with A record data (127.0.0.1)
                                        let name = Name::from_str(question.name().to_string().as_str())
                                            .expect("Failed to parse name");
                                        
                                        let record = Record::from_rdata(
                                            name, 
                                            60,  // TTL (1 minute)
                                            RData::A(hickory_proto::rr::rdata::A::new(127, 0, 0, 1))
                                        );
                                        
                                        // Add the answer to the response
                                        response.add_answer(record);
                                    } else {
                                        println!("Domain {} is not mapped, returning NXDOMAIN", domain);
                                        // Not a domain we care about, return NXDOMAIN to trigger fallback
                                        response.set_response_code(ResponseCode::NXDomain);
                                    }
                                } else {
                                    // Not an A record query, return NXDOMAIN
                                    response.set_response_code(ResponseCode::NXDomain);
                                }
                            }
                        } else {
                            // Not a standard query, return NXDOMAIN
                            response.set_response_code(ResponseCode::NXDomain);
                        }
                        
                        // Convert response to bytes and send
                        if let Ok(response_bytes) = response.to_vec() {
                            if let Err(e) = socket.send_to(&response_bytes, src) {
                                eprintln!("Error sending DNS response: {}", e);
                            }
                        } else {
                            eprintln!("Error serializing DNS response");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving from socket: {}", e);
                }
            }
        }
    }
}

mod https_proxy {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Duration;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    
    // Start the HTTPS proxy as a child process
    pub fn start_https_proxy() -> Result<Child> {
        // Start the HTTPS proxy as a separate process
        let proxy = Command::new("sudo")
            .args(&[
                env::current_exe()?.to_str().unwrap(),
                "run-https-proxy"
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start HTTPS proxy process")?;

        // Wait a moment for the server to start
        thread::sleep(Duration::from_millis(1000));
        
        // TODO: Check if the server is actually running
        
        Ok(proxy)
    }
    
    // This will be called by our "run-https-proxy" command
    pub fn run_server() -> Result<()> {
        println!("Starting HTTPS proxy on 127.0.0.1:443...");
        
        // Load our domain mappings
        let mappings = Arc::new(load_mappings()?);
        
        // Load our CA certificate and key
        let (ca_cert, ca_key) = load_ca()?;
        
        // Create a TCP listener bound to localhost port 443
        let listener = TcpListener::bind("127.0.0.1:443")?;
        println!("HTTPS proxy listening...");
        
        // Accept connections forever
        for stream in listener.incoming() {
            match stream {
                Ok(client_stream) => {
                    // Clone the Arc for this thread
                    let thread_mappings = Arc::clone(&mappings);
                    // Basic connection handling - this is just a placeholder
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(client_stream, &thread_mappings) {
                            eprintln!("Error handling connection: {}", e);
                        }
                    });
                },
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
        
        Ok(())
    }
    
    // Load the CA certificate and key
    fn load_ca() -> Result<(String, String)> {
        let config_dir = get_config_dir()?;
        let ca_cert_path = config_dir.join("ca.pem");
        let ca_key_path = config_dir.join("ca-key.pem");
        
        let cert = fs::read_to_string(ca_cert_path)?;
        let key = fs::read_to_string(ca_key_path)?;
        
        Ok((cert, key))
    }
    
    // NEW: Generate a leaf certificate for a hostname signed by our CA
    fn generate_leaf_cert(hostname: &str, ca_cert_pem: &str, ca_key_pem: &str) -> Result<(Vec<RustlsCertificate>, PrivateKey)> {
        // Reconstruct CA cert with key pair so rcgen can sign
        let ca_key_pair = RcgenKeyPair::from_pem(ca_key_pem)?;
        let ca_params = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem.to_string(), ca_key_pair)?;
        let ca_cert = RcgenCert::from_params(ca_params)?;

        // Build leaf params
        let mut leaf_params = RcgenParams::new(vec![hostname.to_string()])?;
        leaf_params.distinguished_name.push(DnType::CommonName, hostname);
        leaf_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        let leaf_cert = RcgenCert::from_params(leaf_params)?;

        // Serialize leaf cert signed by CA
        let leaf_der = leaf_cert.serialize_der_with_signer(&ca_cert)?;
        let leaf_key_der = leaf_cert.serialize_private_key_der();

        // Build rustls objects
        let cert_chain = vec![RustlsCertificate(leaf_der)];
        let key = PrivateKey(leaf_key_der);
        Ok((cert_chain, key))
    }
    
    // Extract Server Name Indication (SNI) from a TLS ClientHello
    fn extract_sni(data: &[u8]) -> Option<String> {
        // Check if this looks like a TLS handshake
        if data.len() < 5 || data[0] != 0x16 {
            return None;
        }
        
        // TLS record structure:
        // Byte 0: Content Type (0x16 for Handshake)
        // Bytes 1-2: Version (0x0301 for TLS 1.0)
        // Bytes 3-4: Length (big-endian u16)
        
        // Parse the TLS record length
        let record_length = ((data[3] as usize) << 8) | (data[4] as usize);
        if data.len() < 5 + record_length {
            return None;
        }
        
        // Check if this is a ClientHello (handshake type 1)
        if data.len() < 6 || data[5] != 0x01 {
            return None;
        }
        
        // Handshake structure (starts at byte 5):
        // Byte 0: Handshake Type (0x01 for ClientHello)
        // Bytes 1-3: Length (big-endian u24)
        // Followed by ClientHello data
        
        // Skip to session ID length field (5 + 4 + 2 + 32 = 43)
        // 5: TLS record header
        // 4: Handshake header
        // 2: Version
        // 32: Random
        if data.len() < 44 {
            return None;
        }
        
        let mut pos = 43;
        
        // Skip session ID
        let session_id_length = data[pos] as usize;
        pos += 1 + session_id_length;
        if pos + 2 > data.len() {
            return None;
        }
        
        // Skip cipher suites
        let cipher_suites_length = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2 + cipher_suites_length;
        if pos + 1 > data.len() {
            return None;
        }
        
        // Skip compression methods
        let compression_methods_length = data[pos] as usize;
        pos += 1 + compression_methods_length;
        if pos + 2 > data.len() {
            return None;
        }
        
        // Parse extensions
        let extensions_length = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;
        if pos + extensions_length > data.len() {
            return None;
        }
        
        // Iterate through extensions to find SNI (type 0)
        let extensions_end = pos + extensions_length;
        while pos + 4 <= extensions_end {
            let extension_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let extension_length = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            pos += 4;
            
            if extension_type == 0 {
                // This is the SNI extension
                if pos + extension_length <= extensions_end && pos + 2 <= extensions_end {
                    // Skip the SNI list length (2 bytes)
                    let sni_list_length = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                    pos += 2;
                    
                    if pos + sni_list_length <= extensions_end && pos + 1 <= extensions_end {
                        // Check name type (should be 0 for hostname)
                        if data[pos] == 0 {
                            pos += 1;
                            
                            // Parse hostname length
                            if pos + 2 <= extensions_end {
                                let hostname_length = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                                pos += 2;
                                
                                if pos + hostname_length <= extensions_end {
                                    // Extract the hostname as a string
                                    return String::from_utf8(data[pos..pos + hostname_length].to_vec()).ok();
                                }
                            }
                        }
                    }
                }
                
                break;
            }
            
            pos += extension_length;
        }
        
        None
    }
    
    // Handle a single connection
    fn handle_connection(mut client_stream: TcpStream, mappings: &Mappings) -> Result<()> {
        // This is a very basic handler that just prints the first few bytes
        // In a real implementation, we would:
        // 1. Peek at the ClientHello to get the SNI name
        // 2. Generate a certificate for that domain
        // 3. Complete the TLS handshake
        // 4. Parse the HTTP request
        // 5. Rewrite headers if needed
        // 6. Forward to the upstream server
        // 7. Get the response
        // 8. Rewrite response headers if needed
        // 9. Send back to the client
        
        let mut buffer = [0; 1024];
        let n = client_stream.peek(&mut buffer)?;
        
        println!("Received {} bytes", n);
        // Display the first few bytes in hex (for TLS inspection)
        for i in 0..n.min(32) {
            print!("{:02x} ", buffer[i]);
        }
        println!();
        
        // In TLS, the first byte should be 0x16 (TLS Handshake)
        if n > 0 && buffer[0] == 0x16 {
            println!("Looks like a TLS handshake");
            
            // Extract the SNI (Server Name Indication) from the ClientHello
            if let Some(sni) = extract_sni(&buffer[..n]) {
                println!("SNI hostname: {}", sni);
                
                // Check if this domain is in our mappings
                let is_mapped = mappings.domains.contains_key(&sni) || 
                                mappings.domains.values().any(|v| v == &sni);
                                    
                if is_mapped {
                    println!("Domain {} is mapped in our config", sni);

                    // Load CA material
                    let (ca_cert_pem, ca_key_pem) = load_ca()?;

                    // Generate or fetch leaf certificate for this SNI
                    let (cert_chain, priv_key) = generate_leaf_cert(&sni, &ca_cert_pem, &ca_key_pem)?;

                    // Build a rustls ServerConfig for this connection
                    let mut server_config = ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(cert_chain, priv_key)?;
                    server_config.alpn_protocols.push(b"http/1.1".to_vec());

                    let config_arc = StdArc::new(server_config);
                    let mut server_conn = ServerConnection::new(config_arc)?;

                    // Complete handshake, using the existing stream
                    loop {
                        match server_conn.complete_io(&mut client_stream) {
                            Ok((_rd, _wr)) => {
                                if !server_conn.is_handshaking() {
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("TLS handshake error: {}", e);
                                return Ok(());
                            }
                        }
                    }

                    println!("TLS handshake with {} completed", sni);

                    // At this point we have a secure stream. For now just read the first HTTP request line.
                    let mut tls_stream = Stream::new(&mut server_conn, &mut client_stream);
                    let mut http_buf = Vec::new();
                    let _ = tls_stream.read_to_end(&mut http_buf);
                    println!("{} bytes received over TLS", http_buf.len());
                    // TODO: Forward to upstream and relay response.
                    return Ok(());
                } else {
                    println!("Domain {} is not in our mappings", sni);
                    // TODO: Transparent tunnel for unmapped domains
                }
            } else {
                println!("Could not extract SNI from ClientHello");
            }
            
            // Send a simple response to the client to acknowledge
            client_stream.write_all(b"Would process TLS here in a real implementation").ok();
        }
        
        Ok(())
    }
}

fn ensure_daemons_running() -> Result<()> {
    // Start the DNS stub server
    println!("Starting DNS server...");
    let dns_process = dns_server::start_dns_server()?;
    println!("DNS server started");
    
    // Start the HTTPS proxy
    println!("Starting HTTPS proxy...");
    let proxy_process = https_proxy::start_https_proxy()?;
    println!("HTTPS proxy started");
    
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Remap { upstream, alias } => {
            println!("Remapping {} to {}", upstream, alias);
            if let Err(err) = remap(&upstream, &alias) {
                eprintln!("Error: {}", err);
            }
        }
        Commands::List => {
            println!("Listing remaps (TODO)");
        }
        Commands::Remove { alias } => {
            println!("Removing remap for {}", alias);
        }
        Commands::Init => {
            init().unwrap();
        }
        Commands::RunDnsServer => {
            if let Err(err) = dns_server::run_server() {
                eprintln!("DNS server error: {}", err);
            }
        }
        Commands::RunHttpsProxy => {
            if let Err(err) = https_proxy::run_server() {
                eprintln!("HTTPS proxy error: {}", err);
            }
        }
    }
}
