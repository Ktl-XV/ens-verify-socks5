use crate::consts;
use crate::consts::SOCKS5_ADDR_TYPE_IPV4;
use crate::read_exact;
use crate::SocksError;
use anyhow::Context;
use regex::Regex;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::vec::IntoIter;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::lookup_host;

use ethers::prelude::*;

extern crate redis;
use base64::{engine::general_purpose, Engine as _};
use redis::{Commands, SetExpiry, SetOptions};
use rustls;
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::Arc;
use webpki_roots;

use std::io::Write;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime as pkiUnixTime},
    CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
};

use x509_certificate::certificate::X509Certificate;

#[derive(Debug)]
struct MyServerCertVerifier {}

impl ServerCertVerifier for MyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        _ocsp_response: &[u8],
        now: pkiUnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = X509Certificate::from_der(end_entity).unwrap();

        if server_name.to_str() != cert.subject_common_name().unwrap() {
            return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
        }

        if now.as_secs() < cert.validity_not_before().timestamp() as u64 {
            return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
        }

        if now.as_secs() > cert.validity_not_after().timestamp() as u64 {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
/// SOCKS5 reply code
#[derive(Error, Debug)]
pub enum AddrError {
    #[error("DNS Resolution failed")]
    DNSResolutionFailed,
    #[error("Can't read IPv4")]
    IPv4Unreadable,
    #[error("Can't read IPv6")]
    IPv6Unreadable,
    #[error("Can't read port number")]
    PortNumberUnreadable,
    #[error("Can't read domain len")]
    DomainLenUnreadable,
    #[error("Can't read Domain content")]
    DomainContentUnreadable,
    #[error("Malformed UTF-8")]
    Utf8,
    #[error("Unknown address type")]
    IncorrectAddressType,
    #[error("{0}")]
    Custom(String),
}

/// A description of a connection target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    /// Connect to an IP address.
    Ip(SocketAddr),
    /// Connect to a fully qualified domain name.
    ///
    /// The domain name will be passed along to the proxy server and DNS lookup
    /// will happen there.
    Domain(String, u16),
}

impl TargetAddr {
    pub async fn resolve_dns(self) -> anyhow::Result<TargetAddr> {
        let redis_client = redis::Client::open("redis://127.0.0.1/")?;
        let mut redis_con = redis_client.get_connection()?;

        let redis_opts = SetOptions::default().with_expiration(SetExpiry::EX(5)); //TODO: increase
                                                                                  //cache time

        match self {
            TargetAddr::Ip(ip) => Ok(TargetAddr::Ip(ip)),
            TargetAddr::Domain(domain, port) => {
                debug!("Attempt to DNS resolve the domain {}...", &domain);
                let maybe_socket: Option<String> = redis_con.get(&domain)?;

                match maybe_socket {
                    Some(socket) => {
                        debug!("Domain found in cache: {}", domain);

                        Ok(TargetAddr::Ip(
                            SocketAddr::from_str(socket.as_str()).unwrap(),
                        ))
                    }
                    None => {
                        debug!("Domain not found in cache");

                        let re = Regex::new(r"www\..+\.eth").unwrap();
                        let is_www_eth = re.is_match(&domain);
                        let eth_provider = Provider::<Http>::try_from(
                            "https://ethereum-sepolia-rpc.publicnode.com",
                        )?;

                        match is_www_eth {
                            true => {
                                debug!("Looking for www.eth domain");

                                let resolved_socket =
                                    eth_provider.resolve_field(&domain, "socket").await?;
                                let resolved_cert =
                                    eth_provider.resolve_field(&domain, "certificate").await?;

                                let config = ClientConfig::builder()
                                    .dangerous()
                                    .with_custom_certificate_verifier(Arc::new(
                                        MyServerCertVerifier {},
                                    ))
                                    .with_no_client_auth();

                                let rc_config = Arc::new(config);
                                let parsed_domain = domain.clone().try_into().unwrap();

                                let mut client =
                                    rustls::ClientConnection::new(rc_config, parsed_domain)
                                        .unwrap();

                                let mut sock = TcpStream::connect(resolved_socket.clone()).unwrap();

                                let mut tls = rustls::Stream::new(&mut client, &mut sock);
                                tls.write_all(
                                    format!(
                                        concat!(
                                            "GET / HTTP/1.1\r\n",
                                            "Host: {}\r\n",
                                            "Connection: close\r\n",
                                            "Accept-Encoding: identity\r\n",
                                            "\r\n"
                                        ),
                                        domain
                                    )
                                    .as_bytes(),
                                )
                                .unwrap();

                                let server_certs = client.peer_certificates().unwrap();

                                let cert = &server_certs[0];

                                let cert_base64 = general_purpose::STANDARD.encode(cert);

                                if cert_base64 == resolved_cert {
                                    debug!("Key matches DNS secure, adding to cache");
                                    let socket_addr =
                                        SocketAddr::from_str(resolved_socket.as_str()).unwrap();

                                    redis_con.set_options(
                                        &domain,
                                        format!("{:?}", socket_addr),
                                        redis_opts,
                                    )?;
                                    Ok(TargetAddr::Ip(socket_addr))
                                } else {
                                    error!("Key does not match, blocking");

                                    Err(AddrError::Custom(
                                        "Possibly fake certificate detected".to_string(),
                                    )
                                    .into())
                                }
                            }
                            false => {
                                let socket_addr = lookup_host((&domain[..], port))
                                    .await
                                    .context(AddrError::DNSResolutionFailed)?
                                    .next()
                                    .ok_or(AddrError::Custom(
                                        "Can't fetch DNS to the domain.".to_string(),
                                    ))?;
                                debug!("domain name resolved to {}", socket_addr);

                                if port == 443 {
                                    let maybe_cert =
                                        eth_provider.resolve_field(&domain, "certificate").await;

                                    match maybe_cert {
                                        Ok(ens_cert) => {
                                            let root_store = rustls::RootCertStore::from_iter(
                                                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                                            );
                                            let config = rustls::ClientConfig::builder()
                                                .with_root_certificates(root_store)
                                                .with_no_client_auth();
                                            let rc_config = Arc::new(config);
                                            let parsed_domain = domain.clone().try_into().unwrap();

                                            let mut client = rustls::ClientConnection::new(
                                                rc_config,
                                                parsed_domain,
                                            )
                                            .unwrap();

                                            let mut sock =
                                                TcpStream::connect(format!("{}:443", domain))
                                                    .unwrap();

                                            let mut tls =
                                                rustls::Stream::new(&mut client, &mut sock);
                                            tls.write_all(
                                                format!(
                                                    concat!(
                                                        "GET / HTTP/1.1\r\n",
                                                        "Host: {}\r\n",
                                                        "Connection: close\r\n",
                                                        "Accept-Encoding: identity\r\n",
                                                        "\r\n"
                                                    ),
                                                    domain
                                                )
                                                .as_bytes(),
                                            )
                                            .unwrap();

                                            let server_certs = client.peer_certificates().unwrap();

                                            let cert = &server_certs[0];

                                            let cert_base64 =
                                                general_purpose::STANDARD.encode(cert);

                                            if cert_base64 == ens_cert {
                                                debug!("Key matches DNS secure, adding to cache");
                                                redis_con.set_options(
                                                    &domain,
                                                    format!("{:?}", socket_addr),
                                                    redis_opts,
                                                )?;
                                                return Ok(TargetAddr::Ip(socket_addr));
                                            } else {
                                                error!("Key does not match, blocking");

                                                return Err(AddrError::Custom(
                                                    "Possibly fake certificate detected"
                                                        .to_string(),
                                                )
                                                .into());
                                            }
                                        }
                                        Err(_) => {
                                            debug!("No ENS");
                                            redis_con.set_options(
                                                &domain,
                                                format!("{:?}", socket_addr),
                                                redis_opts,
                                            )?;
                                        }
                                    }
                                }
                                Ok(TargetAddr::Ip(socket_addr))
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, TargetAddr::Ip(_))
    }

    pub fn is_domain(&self) -> bool {
        !self.is_ip()
    }

    pub fn to_be_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![];
        match self {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                debug!("TargetAddr::IpV4");

                buf.extend_from_slice(&[SOCKS5_ADDR_TYPE_IPV4]);

                debug!("addr ip {:?}", (*addr.ip()).octets());
                buf.extend_from_slice(&(addr.ip()).octets()); // ip
                buf.extend_from_slice(&addr.port().to_be_bytes()); // port
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                debug!("TargetAddr::IpV6");
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_TYPE_IPV6]);

                debug!("addr ip {:?}", (*addr.ip()).octets());
                buf.extend_from_slice(&(addr.ip()).octets()); // ip
                buf.extend_from_slice(&addr.port().to_be_bytes()); // port
            }
            TargetAddr::Domain(ref domain, port) => {
                debug!("TargetAddr::Domain");
                if domain.len() > u8::max_value() as usize {
                    return Err(SocksError::ExceededMaxDomainLen(domain.len()).into());
                }
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME, domain.len() as u8]);
                buf.extend_from_slice(domain.as_bytes()); // domain content
                buf.extend_from_slice(&port.to_be_bytes());
                // port content (.to_be_bytes() convert from u16 to u8 type)
            }
        }
        Ok(buf)
    }
}

// async-std ToSocketAddrs doesn't supports external trait implementation
// @see https://github.com/async-rs/async-std/issues/539
impl std::net::ToSocketAddrs for TargetAddr {
    type Iter = IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<IntoIter<SocketAddr>> {
        match *self {
            TargetAddr::Ip(addr) => Ok(vec![addr].into_iter()),
            TargetAddr::Domain(_, _) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Domain name has to be explicitly resolved, please use TargetAddr::resolve_dns().",
            )),
        }
    }
}

impl fmt::Display for TargetAddr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TargetAddr::Ip(ref addr) => write!(f, "{}", addr),
            TargetAddr::Domain(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

/// A trait for objects that can be converted to `TargetAddr`.
pub trait ToTargetAddr {
    /// Converts the value of `self` to a `TargetAddr`.
    fn to_target_addr(&self) -> io::Result<TargetAddr>;
}

impl<'a> ToTargetAddr for (&'a str, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        // try to parse as an IP first
        if let Ok(addr) = self.0.parse::<Ipv4Addr>() {
            return (addr, self.1).to_target_addr();
        }

        if let Ok(addr) = self.0.parse::<Ipv6Addr>() {
            return (addr, self.1).to_target_addr();
        }

        Ok(TargetAddr::Domain(self.0.to_owned(), self.1))
    }
}

impl ToTargetAddr for SocketAddr {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        Ok(TargetAddr::Ip(*self))
    }
}

impl ToTargetAddr for SocketAddrV4 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V4(*self).to_target_addr()
    }
}

impl ToTargetAddr for SocketAddrV6 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V6(*self).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv4Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV4::new(self.0, self.1).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv6Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV6::new(self.0, self.1, 0, 0).to_target_addr()
    }
}

#[derive(Debug)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String), // Vec<[u8]> or Box<[u8]> or String ?
}

/// This function is used by the client & the server
pub async fn read_address<T: AsyncRead + Unpin>(
    stream: &mut T,
    atyp: u8,
) -> anyhow::Result<TargetAddr> {
    let addr = match atyp {
        consts::SOCKS5_ADDR_TYPE_IPV4 => {
            debug!("Address type `IPv4`");
            Addr::V4(read_exact!(stream, [0u8; 4]).context(AddrError::IPv4Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_IPV6 => {
            debug!("Address type `IPv6`");
            Addr::V6(read_exact!(stream, [0u8; 16]).context(AddrError::IPv6Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            debug!("Address type `domain`");
            let len = read_exact!(stream, [0]).context(AddrError::DomainLenUnreadable)?[0];
            let domain = read_exact!(stream, vec![0u8; len as usize])
                .context(AddrError::DomainContentUnreadable)?;
            // make sure the bytes are correct utf8 string
            let domain = String::from_utf8(domain).context(AddrError::Utf8)?;

            Addr::Domain(domain)
        }
        _ => return Err(anyhow::anyhow!(AddrError::IncorrectAddressType)),
    };

    // Find port number
    let port = read_exact!(stream, [0u8; 2]).context(AddrError::PortNumberUnreadable)?;
    // Convert (u8 * 2) into u16
    let port = (port[0] as u16) << 8 | port[1] as u16;

    // Merge ADDRESS + PORT into a TargetAddr
    let addr: TargetAddr = match addr {
        Addr::V4([a, b, c, d]) => (Ipv4Addr::new(a, b, c, d), port).to_target_addr()?,
        Addr::V6(x) => (Ipv6Addr::from(x), port).to_target_addr()?,
        Addr::Domain(domain) => TargetAddr::Domain(domain, port),
    };

    Ok(addr)
}
