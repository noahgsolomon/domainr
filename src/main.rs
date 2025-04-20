use clap::{Parser, Subcommand};
use rcgen::{Certificate, CertificateParams, IsCa, BasicConstraints, KeyPair};
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
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::Stream;
use rcgen::{CertificateParams as RcgenParams, Certificate as RcgenCert, DnType, SanType, KeyPair as RcgenKeyPair};
use std::sync::Arc as StdArc; // avoid conflict with super::Arc
use pem;
use native_tls;

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
                                                   mappings.domains.values().any(|v| v == domain) ||
                                                   is_subdomain_of_mapped_domain(domain, &mappings);
                                    
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
    
    // Helper function to check if a domain is a subdomain of any mapped domain
    fn is_subdomain_of_mapped_domain(domain: &str, mappings: &Mappings) -> bool {
        // Check if this is a subdomain of any upstream domain
        for upstream in mappings.domains.values() {
            if domain == upstream {
                return true;
            }
            
            // Check if it's a subdomain (e.g., api.x.com when x.com is an upstream)
            if domain.ends_with(&format!(".{}", upstream)) {
                return true;
            }
        }
        
        // Check if this is a subdomain of any alias domain
        for alias in mappings.domains.keys() {
            if domain == alias {
                return true;
            }
            
            // Check if it's a subdomain (e.g., api.a.a when a.a is an alias)
            if domain.ends_with(&format!(".{}", alias)) {
                return true;
            }
        }
        
        false
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
    
    // Generate a certificate for a hostname signed by our CA
    fn generate_leaf_cert(hostname: &str, ca_cert_pem: &str, ca_key_pem: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Parse the CA key
        let ca_key_pair = KeyPair::from_pem(ca_key_pem)?;
        
        // Create the leaf certificate parameters with proper SAN entries
        let mut cert_domains = vec![hostname.to_string()];
        
        // Add wildcard domain as a SAN for better compatibility
        if hostname.split('.').count() > 1 && !hostname.parse::<IpAddr>().is_ok() {
            // For a domain like "example.com" add "*.example.com"
            cert_domains.push(format!("*.{}", hostname));
            
            // If this is already a subdomain, also add the base domain
            // For "api.example.com", extract and add "example.com"
            let parts: Vec<&str> = hostname.split('.').collect();
            if parts.len() > 2 {
                let base_domain = parts[parts.len()-2..].join(".");
                cert_domains.push(base_domain.clone());
                cert_domains.push(format!("*.{}", base_domain));
            }
        }
        
        // Create certificate parameters with all domains
        let mut params = CertificateParams::new(cert_domains)?;
        
        // Set proper certificate attributes
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.is_ca = IsCa::ExplicitNoCa;
        
        // Add key usage extensions for proper validation
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        
        // Add extended key usage for TLS web server and client authentication
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        
        // Create a leaf key pair
        let leaf_key_pair = KeyPair::generate()?;
        
        // Parse the CA certificate from PEM
        let ca_cert_pem_data = pem::parse(ca_cert_pem)
            .context("Failed to parse CA certificate PEM")?;
            
        // Create a simple CA certificate that can be used for signing
        let mut ca_params = CertificateParams::new(vec![])?;
        ca_params.distinguished_name.push(DnType::CommonName, "domainr-root-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key_pair)?;
        
        // Sign the leaf certificate with the CA
        let leaf_cert = params.signed_by(&leaf_key_pair, &ca_cert, &ca_key_pair)?;
        
        // Extract the CA certificate in DER format
        let ca_cert_der = ca_cert_pem_data.contents().to_vec();
        
        // Create the certificate chain - we need both the leaf and CA certificates
        let cert_chain = vec![
            // Leaf certificate first
            CertificateDer::from(leaf_cert.der().to_vec()),
            // Then the CA certificate
            CertificateDer::from(ca_cert_der),
        ];
        
        // Private key from the leaf certificate
        let key_der = leaf_key_pair.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der)
        );
        
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
                let upstream_domain = if let Some(upstream) = mappings.domains.get(&sni) {
                    println!("Found mapping: {} -> {}", sni, upstream);
                    upstream.clone()
                } else if mappings.domains.values().any(|v| v == &sni) {
                    println!("This is an upstream domain in our mappings");
                    sni.clone()
                } else {
                    println!("Domain {} is not in our mappings", sni);
                    sni.clone()
                };
                
                // Proceed with TLS handling for all domains
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

                // At this point we have a secure stream
                let mut tls_stream = Stream::new(&mut server_conn, &mut client_stream);
                
                // Parse the HTTP request
                let mut request_buffer = Vec::new();
                let mut headers_end = None;
                let mut total_read = 0;
                
                // Read data until we find the end of headers (marked by "\r\n\r\n")
                let mut temp_buffer = [0; 4096];
                while headers_end.is_none() {
                    match tls_stream.read(&mut temp_buffer) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            request_buffer.extend_from_slice(&temp_buffer[..n]);
                            total_read += n;
                            
                            // Search for end of headers
                            if request_buffer.len() >= 4 {
                                for i in 0..request_buffer.len() - 3 {
                                    if &request_buffer[i..i+4] == b"\r\n\r\n" {
                                        headers_end = Some(i + 4);
                                        break;
                                    }
                                }
                            }
                            
                            // Don't read too much data
                            if total_read > 1024 * 1024 { // 1MB limit
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading HTTP request: {}", e);
                            return Ok(());
                        }
                    }
                }
                
                // Convert to string for parsing
                if let Some(headers_end) = headers_end {
                    let headers_str = String::from_utf8_lossy(&request_buffer[..headers_end]);
                    let headers_lines: Vec<&str> = headers_str.lines().collect();
                    
                    if headers_lines.is_empty() {
                        eprintln!("Invalid HTTP request: no headers");
                        return Ok(());
                    }
                    
                    // Parse request line
                    let request_parts: Vec<&str> = headers_lines[0].split_whitespace().collect();
                    if request_parts.len() < 3 {
                        eprintln!("Invalid HTTP request line: {}", headers_lines[0]);
                        return Ok(());
                    }
                    
                    let method = request_parts[0];
                    let path = request_parts[1];
                    let version = request_parts[2];
                    
                    println!("HTTP request: {} {} {}", method, path, version);
                    
                    // Extract host header
                    let mut host_header = None;
                    for line in &headers_lines[1..] {
                        if line.to_lowercase().starts_with("host:") {
                            host_header = Some(line.trim_start_matches("host:").trim());
                            break;
                        }
                    }
                    
                    if let Some(host) = host_header {
                        println!("Host header: {}", host);
                        
                        // Modify the request to target the upstream server
                        let modified_request = create_modified_request(
                            &request_buffer, 
                            &headers_lines,
                            headers_end,
                            &sni,
                            &upstream_domain
                        )?;
                        
                        // Connect to the upstream server
                        if let Err(e) = forward_to_upstream(
                            &modified_request,
                            &upstream_domain,
                            &mut tls_stream
                        ) {
                            eprintln!("Error forwarding to upstream: {}", e);
                        }
                    } else {
                        eprintln!("No Host header found in request");
                    }
                } else {
                    eprintln!("Could not find end of HTTP headers");
                }
                
                return Ok(());
            } else {
                println!("Could not extract SNI from ClientHello");
            }
            
            // Send a simple response to the client to acknowledge
            client_stream.write_all(b"Would process TLS here in a real implementation").ok();
        }
        
        Ok(())
    }
    
    // Create a modified HTTP request to forward to the upstream server
    fn create_modified_request(
        original_request: &[u8],
        headers_lines: &[&str],
        headers_end: usize,
        original_domain: &str,
        upstream_domain: &str,
    ) -> Result<Vec<u8>> {
        let mut modified_request = Vec::new();
        
        // Extract the first line (method, path, version)
        let request_line_parts: Vec<&str> = headers_lines[0].split_whitespace().collect();
        if request_line_parts.len() < 3 {
            anyhow::bail!("Invalid request line");
        }
        
        // Add the request line unchanged
        modified_request.extend_from_slice(headers_lines[0].as_bytes());
        modified_request.extend_from_slice(b"\r\n");
        
        // Keep track of the original Host header value for rewriting URLs
        let mut original_host = original_domain.to_string();
        
        // Add all headers except Host, modifying as needed
        for &line in &headers_lines[1..] {
            if line.is_empty() {
                continue;
            }
            
            if line.to_lowercase().starts_with("host:") {
                // Extract the original host value for later use
                let host_parts: Vec<&str> = line.splitn(2, ':').collect();
                if host_parts.len() > 1 {
                    original_host = host_parts[1].trim().to_string();
                }
                
                // Replace the host header with the upstream domain
                modified_request.extend_from_slice(b"Host: ");
                modified_request.extend_from_slice(upstream_domain.as_bytes());
                modified_request.extend_from_slice(b"\r\n");
            } else if line.to_lowercase().starts_with("origin:") {
                // Replace Origin header to avoid CORS issues
                let new_origin = format!("Origin: https://{}", upstream_domain);
                modified_request.extend_from_slice(new_origin.as_bytes());
                modified_request.extend_from_slice(b"\r\n");
            } else if line.to_lowercase().starts_with("referer:") {
                // Rewrite Referer header to use upstream domain
                let referer_parts: Vec<&str> = line.splitn(2, ':').collect();
                if referer_parts.len() > 1 {
                    let referer_value = referer_parts[1].trim();
                    let new_referer = referer_value.replace(&original_host, upstream_domain);
                    modified_request.extend_from_slice(b"Referer: ");
                    modified_request.extend_from_slice(new_referer.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                } else {
                    // Keep original if we can't parse it
                    modified_request.extend_from_slice(line.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }
            } else {
                // Keep other headers as is
                modified_request.extend_from_slice(line.as_bytes());
                modified_request.extend_from_slice(b"\r\n");
            }
        }
        
        // Add CORS headers to allow cross-origin requests
        modified_request.extend_from_slice(b"X-Forwarded-Host: ");
        modified_request.extend_from_slice(original_host.as_bytes());
        modified_request.extend_from_slice(b"\r\n");
        
        // End of headers
        modified_request.extend_from_slice(b"\r\n");
        
        // Append the body if any, rewriting domain references if needed
        if original_request.len() > headers_end {
            let body = &original_request[headers_end..];
            
            // For JSON, HTML, or text bodies, rewrite domain references
            let content_type = headers_lines.iter()
                .find(|&line| line.to_lowercase().starts_with("content-type:"))
                .map(|&line| line.to_lowercase());
                
            if let Some(ct) = content_type {
                if ct.contains("json") || ct.contains("html") || ct.contains("text") {
                    // Try to rewrite the body if it's text-based
                    if let Ok(body_str) = String::from_utf8(body.to_vec()) {
                        // Replace all occurrences of the original domain with the upstream domain
                        let modified_body = body_str.replace(&original_host, upstream_domain);
                        modified_request.extend_from_slice(modified_body.as_bytes());
                    } else {
                        // If not valid UTF-8, keep the original body
                        modified_request.extend_from_slice(body);
                    }
                } else {
                    // Binary data, keep as is
                    modified_request.extend_from_slice(body);
                }
            } else {
                // No content type, keep as is
                modified_request.extend_from_slice(body);
            }
        }
        
        Ok(modified_request)
    }
    
    // Forward the request to the upstream server and relay the response back
    fn forward_to_upstream(
        request: &[u8],
        upstream_domain: &str,
        client_tls_stream: &mut Stream<ServerConnection, TcpStream>,
    ) -> Result<()> {
        println!("Forwarding request to upstream: {}", upstream_domain);
        
        // Connect to the upstream server using native-tls which uses the system's certificate store
        let upstream_addr = format!("{}:443", upstream_domain);
        
        // Create a TLS connector using native-tls
        let tls_connector = native_tls::TlsConnector::builder()
            .build()
            .context("Failed to create TLS connector")?;
            
        // Connect to the server
        let tcp_stream = TcpStream::connect(&upstream_addr)
            .context(format!("Failed to connect to upstream: {}", upstream_addr))?;
            
        // Set TCP options
        tcp_stream.set_nodelay(true)?;
        
        // Establish TLS connection
        let mut tls_stream = tls_connector.connect(upstream_domain, tcp_stream)
            .context(format!("Failed to establish TLS connection to {}", upstream_domain))?;
        
        // Send the request to the upstream server
        tls_stream.write_all(request)
            .context("Failed to send request to upstream server")?;
        
        // Read the response headers
        let mut response_buffer = Vec::new();
        let mut headers_end = None;
        let mut buffer = [0; 8192];
        
        // Read data until we find the end of headers (marked by "\r\n\r\n")
        while headers_end.is_none() {
            match tls_stream.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    response_buffer.extend_from_slice(&buffer[..n]);
                    
                    // Search for end of headers
                    if response_buffer.len() >= 4 {
                        for i in 0..response_buffer.len() - 3 {
                            if &response_buffer[i..i+4] == b"\r\n\r\n" {
                                headers_end = Some(i + 4);
                                break;
                            }
                        }
                    }
                    
                    // If we have the headers, break the loop
                    if headers_end.is_some() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading response: {}", e);
                    return Err(anyhow::anyhow!("Error reading response: {}", e));
                }
            }
        }
        
        // Process and rewrite the response headers if needed
        let modified_response = if let Some(headers_end) = headers_end {
            let mut modified_response = Vec::new();
            
            // Convert to string for parsing
            let headers_str = String::from_utf8_lossy(&response_buffer[..headers_end]);
            let headers_lines: Vec<&str> = headers_str.lines().collect();
            
            if !headers_lines.is_empty() {
                // Add the status line unchanged
                modified_response.extend_from_slice(headers_lines[0].as_bytes());
                modified_response.extend_from_slice(b"\r\n");
                
                // Process headers, modifying as needed
                for &line in &headers_lines[1..] {
                    if line.is_empty() {
                        continue;
                    }
                    
                    // Skip any Access-Control-* headers, we'll add our own
                    if line.to_lowercase().starts_with("access-control-") {
                        continue;
                    }
                    
                    // Keep other headers as is
                    modified_response.extend_from_slice(line.as_bytes());
                    modified_response.extend_from_slice(b"\r\n");
                }
                
                // Add CORS headers to allow our remapped domain
                modified_response.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
                modified_response.extend_from_slice(b"Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n");
                modified_response.extend_from_slice(b"Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
                modified_response.extend_from_slice(b"Access-Control-Allow-Credentials: true\r\n");
                
                // End of headers
                modified_response.extend_from_slice(b"\r\n");
                
                // Append response body we already have
                if response_buffer.len() > headers_end {
                    modified_response.extend_from_slice(&response_buffer[headers_end..]);
                }
            } else {
                modified_response = response_buffer;
            }
            
            modified_response
        } else {
            // No headers found, just use the original response
            response_buffer
        };
        
        // Send the modified response headers to the client
        client_tls_stream.write_all(&modified_response)
            .context("Failed to write modified response headers to client")?;
        
        // Continue reading and forwarding the rest of the response
        let mut total_bytes = modified_response.len();
        
        loop {
            match tls_stream.read(&mut buffer) {
                Ok(0) => break, // End of stream
                Ok(n) => {
                    // Forward this chunk to the client
                    client_tls_stream.write_all(&buffer[..n])
                        .context("Failed to write response to client")?;
                    total_bytes += n;
                }
                Err(e) => {
                    eprintln!("Error reading from upstream: {}", e);
                    break;
                }
            }
        }
        
        println!("Forwarded {} bytes from upstream to client", total_bytes);
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
