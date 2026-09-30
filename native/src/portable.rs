//! Versioned portable MPC-TLS presentations. No X credentials leave the prover.
use async_tungstenite::{
    tokio::{accept_hdr_async_with_config, connect_async},
    tungstenite::client::IntoClientRequest,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bincode::Options;
use eyre::{ensure, Result};
use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde_json::{json, Value};
use std::{future::IntoFuture, sync::Arc, time::Duration};
use tlsn::{
    attestation::{
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        signing::KeyAlgId,
        Attestation, AttestationConfig, CryptoProvider, Extension, InvalidExtension,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::VerifierCommitStart,
    webpki::RootCertStore,
    Session,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use ws_stream_tungstenite::WsStream;
const EXT: &[u8] = b"proof-inbox.agent-key.v1";
const MAX: usize = 262144;
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX, "oversize");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}
async fn receive<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    s.read_exact(&mut prefix).await?;
    let n = u32::from_be_bytes(prefix) as usize;
    ensure!(n > 0 && n <= MAX, "frame size");
    let mut bytes = vec![0; n];
    s.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn send<S: AsyncWrite + Unpin>(s: &mut S, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX, "frame size");
    s.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    s.write_all(bytes).await?;
    s.flush().await?;
    Ok(())
}
fn provider() -> Result<CryptoProvider> {
    Ok(CryptoProvider {
        cert: tlsn::verifier::ServerCertVerifier::new(&RootCertStore::mozilla())?,
        ..Default::default()
    })
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| eyre::eyre!("missing field"))
}
// Spawned drivers must be cancelled on every failure/timeout, including before MPC completes.
struct Driver<T>(Option<tokio::task::JoinHandle<T>>);
impl<T> Drop for Driver<T> {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            t.abort();
        }
    }
}
impl<T> Driver<T> {
    async fn join(&mut self) -> Result<T> {
        let out = self.0.as_mut().unwrap().await?;
        self.0.take();
        Ok(out)
    }
}

pub async fn prove(v: Value) -> Result<Value> {
    prove_with(v, "x.com", ("x.com", 443), RootCertStore::mozilla()).await
}
async fn prove_with(
    v: Value,
    domain: &str,
    address: (&str, u16),
    roots: RootCertStore,
) -> Result<Value> {
    let endpoint = field(&v, "notaryUrl")?;
    let uri = endpoint.parse::<async_tungstenite::tungstenite::http::Uri>()?;
    ensure!(
        uri.path() == "/notarize" && uri.query().is_none(),
        "notary path"
    );
    ensure!(
        uri.scheme_str() == Some("wss")
            || (uri.scheme_str() == Some("ws")
                && matches!(uri.host(), Some("localhost" | "127.0.0.1"))),
        "secure notary required"
    );
    let key = field(&v, "publicKey")?;
    ensure!(
        key.len() <= 200 && key.starts_with("-----BEGIN PUBLIC KEY-----"),
        "agent key"
    );
    let path = field(&v, "path")?;
    ensure!(
        path.starts_with("/i/api/graphql/")
            && path.contains("/Viewer?")
            && !path.contains(['\r', '\n', ' ']),
        "endpoint"
    );
    let line = format!("GET {path} HTTP/1.1\r\n");
    let mut request =
        format!("{line}Host: x.com\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
    for name in [
        "cookie",
        "authorization",
        "x-csrf-token",
        "x-client-transaction-id",
    ] {
        if let Some(s) = v["headers"][name].as_str() {
            ensure!(!s.contains(['\r', '\n']), "header");
            request.push_str(&format!("{name}: {s}\r\n"));
        }
    }
    request.push_str("\r\n");
    ensure!(request.len() <= 4096, "request limit");
    let mut req = endpoint.into_client_request()?;
    if let Some(token) = v["notaryToken"].as_str() {
        req.headers_mut()
            .insert("authorization", format!("Bearer {token}").parse()?);
    }
    let (socket, _) = connect_async(req).await?;
    let (driver, mut handle) = Session::new(WsStream::new(socket)).split();
    let mut task = Driver(Some(tokio::spawn(driver)));
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(4096)
                .max_recv_data(16384)
                .build()?,
        )
        .await?;
    let remote = tokio::net::TcpStream::connect(address).await?;
    let (connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(domain.try_into()?))
            .root_store(roots.clone())
            .build()?,
        remote.compat(),
    )?;
    let mut ptask = Driver(Some(tokio::spawn(prover.into_future())));
    let mut connection = connection;
    connection.write_all(request.as_bytes()).await?;
    connection.flush().await?;
    let mut response = Vec::new();
    connection.read_to_end(&mut response).await?;
    drop(connection);
    // Never export an account session cookie if X refreshes it in the response.
    let response_lower = String::from_utf8_lossy(&response).to_ascii_lowercase();
    ensure!(
        !response_lower.contains("auth_token=")
            && !response_lower.contains("authorization: bearer"),
        "sensitive response"
    );
    let mut prover = ptask.join().await??;
    let transcript = prover.transcript().clone();
    let tls = prover.tls_transcript().clone();
    let len = transcript.received().len();
    let mut commit = TranscriptCommitConfig::builder(&transcript);
    commit
        .commit_sent(&(0..line.len()))?
        .commit_recv(&(0..len))?;
    let mut rc = RequestConfig::builder();
    rc.transcript_commit(commit.build()?);
    rc.extension(Extension {
        id: EXT.to_vec(),
        value: key.as_bytes().to_vec(),
    });
    let rc = rc.build()?;
    let mut pc = ProveConfig::builder(&transcript);
    pc.transcript_commit(rc.transcript_commit().unwrap().clone());
    let out = prover.prove(&pc.build()?).await?;
    prover.close().await?;
    let provider = CryptoProvider {
        cert: tlsn::verifier::ServerCertVerifier::new(&roots)?,
        ..Default::default()
    };
    let mut builder = AttestationRequest::builder(&rc);
    builder
        .server_name(ServerName::Dns(domain.try_into()?))
        .handshake_data(HandshakeData {
            certs: tls
                .server_cert_chain()
                .ok_or_else(|| eyre::eyre!("certs"))?
                .to_vec(),
            sig: tls
                .server_signature()
                .ok_or_else(|| eyre::eyre!("sig"))?
                .clone(),
            binding: tls.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(out.transcript_secrets, out.transcript_commitments);
    let (req, secrets) = builder.build(&provider)?;
    handle.close();
    let mut socket = task.join().await??;
    send(&mut socket, &bincode::serialize(&req)?).await?;
    let att: Attestation = decode(&receive(&mut socket).await?)?;
    req.validate(&att, &provider)?;
    let expected = field(&v, "notaryKey")?;
    ensure!(
        att.body.verifying_key().alg == KeyAlgId::K256
            && hex::encode(&att.body.verifying_key().data) == expected,
        "untrusted notary"
    );
    let mut transcript_proof = secrets.transcript_proof_builder();
    transcript_proof
        .reveal_sent(&(0..line.len()))?
        .reveal_recv(&(0..len))?;
    let mut presentation = att.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof.build()?);
    // Only the shareable presentation is persisted. Transcript secrets (including cookies) are dropped.
    let bytes = bincode::serialize(&presentation.build()?)?;
    ensure!(bytes.len() <= MAX, "presentation limit");
    Ok(json!({"format":"tlsn-inbox-v1","presentation":STANDARD.encode(bytes)}))
}

pub fn verify(v: Value) -> Result<Value> {
    verify_with(v, &provider()?)
}
fn verify_with(v: Value, provider: &CryptoProvider) -> Result<Value> {
    let bytes = STANDARD.decode(field(&v, "presentation")?)?;
    let p: Presentation = decode(&bytes)?;
    let key = p.verifying_key();
    ensure!(key.alg == KeyAlgId::K256, "key algorithm");
    let notary_key = hex::encode(&key.data);
    ensure!(
        v["trustedNotaryKeys"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(notary_key.as_str()))),
        "untrusted notary"
    );
    let out = p.verify(provider)?;
    ensure!(
        out.extensions.len() == 1
            && out.extensions[0].id == EXT
            && out.extensions[0].value.len() <= 200,
        "agent binding"
    );
    let subject = String::from_utf8(out.extensions[0].value.clone())?;
    let mut t = out.transcript.ok_or_else(|| eyre::eyre!("transcript"))?;
    ensure!(
        t.len_sent() <= 4096 && t.len_received() <= 16384 && t.len_received() > 0,
        "transcript size"
    );
    ensure!(t.received_unauthed().is_empty(), "full response required");
    t.set_unauthed(0);
    let sent = t.sent_unsafe();
    let end = sent
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| eyre::eyre!("request line"))?
        + 2;
    ensure!(
        !sent[..end].contains(&0),
        "authenticated request line required"
    );
    Ok(
        json!({"server_name":out.server_name.ok_or_else(||eyre::eyre!("server"))?.to_string(),"subject":subject,"notaryKey":notary_key,"time":out.connection_info.time,"transcript":{"sent":std::str::from_utf8(&sent[..end])?,"recv":std::str::from_utf8(t.received_unsafe())?}}),
    )
}

pub async fn serve(v: Value) -> Result<()> {
    let private = hex::decode(field(&v, "privateKey")?)?;
    let token = field(&v, "token")?.to_owned();
    ensure!(token.len() >= 32, "notary invitation required");
    let mut check = CryptoProvider::default();
    check.signer.set_secp256k1(&private)?;
    let port = v["port"].as_u64().unwrap_or(7048);
    ensure!(port > 0 && port <= 65535, "port");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port as u16)).await?;
    let sem = Arc::new(tokio::sync::Semaphore::new(2));
    let mut window = std::time::Instant::now();
    let mut attempts = 0;
    println!("{{\"ready\":true,\"port\":{port}}}");
    loop {
        let (socket, _) = listener.accept().await?;
        if window.elapsed() > Duration::from_secs(60) {
            window = std::time::Instant::now();
            attempts = 0;
        }
        attempts += 1;
        if attempts > 10 {
            continue;
        }
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            continue;
        };
        let token = token.clone();
        let private = private.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(Duration::from_secs(150), async move {
                let socket = accept_hdr_async_with_config(
                    socket,
                    move |req: &async_tungstenite::tungstenite::handshake::server::Request, res| {
                        if req.uri().path() != "/notarize"
                            || req.uri().query().is_some()
                            || req.headers().contains_key("origin")
                            || req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                != Some(format!("Bearer {token}").as_str())
                        {
                            return Err(async_tungstenite::tungstenite::http::Response::builder()
                                .status(403)
                                .body(Some("Denied".into()))
                                .unwrap());
                        }
                        Ok(res)
                    },
                    Some(
                        async_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                            .max_message_size(Some(1048576))
                            .max_frame_size(Some(1048576)),
                    ),
                )
                .await?;
                notarize(WsStream::new(socket), &private).await
            })
            .await;
        });
    }
}
async fn notarize<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: S,
    key: &[u8],
) -> Result<()> {
    let (driver, mut handle) = Session::new(socket).split();
    let mut task = Driver(Some(tokio::spawn(driver)));
    let verifier = match handle
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore::mozilla())
                .build()?,
        )?
        .commit()
        .await?
    {
        VerifierCommitStart::Mpc(v) => {
            ensure!(
                v.config().max_sent_data() <= 4096 && v.config().max_recv_data() <= 16384,
                "limits"
            );
            v.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(v) => {
            v.reject(Some("MPC required")).await?;
            return Err(eyre::eyre!("MPC required"));
        }
    };
    let (out, verifier) = verifier.verify().await?.accept().await?;
    let tls = verifier.tls_transcript().clone();
    verifier.close().await?;
    handle.close();
    let mut socket = task.join().await??;
    let request: AttestationRequest = decode(&receive(&mut socket).await?)?;
    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(key)?;
    let mut config = AttestationConfig::builder();
    config.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    config.extension_validator(|extensions| {
        if extensions.len() != 1
            || extensions[0].id != EXT
            || extensions[0].value.len() > 200
            || !extensions[0]
                .value
                .starts_with(b"-----BEGIN PUBLIC KEY-----")
        {
            return Err(InvalidExtension::new("agent key required"));
        }
        Ok(())
    });
    let config = config.build()?;
    let CertBinding::V1_2(binding) = tls.certificate_binding() else {
        return Err(eyre::eyre!("TLS version"));
    };
    let mut builder = Attestation::builder(&config).accept_request(request)?;
    let length = |records: &[tlsn::transcript::Record]| {
        records
            .iter()
            .filter(|r| r.typ == ContentType::ApplicationData)
            .map(|r| r.ciphertext.len())
            .sum::<usize>() as u32
    };
    builder
        .connection_info(ConnectionInfo {
            time: tls.time(),
            version: tls.version(),
            transcript_length: TranscriptLength {
                sent: length(tls.sent()),
                received: length(tls.recv()),
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(out.transcript_commitments);
    send(
        &mut socket,
        &bincode::serialize(&builder.build(&provider)?)?,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            ServerConfig,
        },
        TlsAcceptor,
    };

    use tlsn::attestation::signing::{Secp256k1Signer, Signer};
    #[tokio::test(flavor = "multi_thread")]
    async fn portable_mpc_roundtrip_and_adversarial_verification() -> Result<()> {
        let roots = RootCertStore {
            roots: vec![tlsn::webpki::CertificateDer(CA_CERT_DER.to_vec())],
        };
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(SERVER_CERT_DER.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(SERVER_KEY_DER.to_vec())),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tls_port = listener.local_addr()?.port();
        let tls_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut req = Vec::new();
            let mut byte = [0; 1];
            while !req.ends_with(b"\r\n\r\n") {
                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte)
                    .await
                    .unwrap();
                req.push(byte[0]);
            }
            assert!(String::from_utf8_lossy(&req).contains("cookie: secret-cookie"));
            tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut stream)
                .await
                .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let notary_task = tokio::spawn(async move {
            let (s, _) = listener.accept().await?;
            let ws = async_tungstenite::tokio::accept_async(s).await?;
            let r = notarize(WsStream::new(ws), &[1u8; 32]).await;
            if let Err(e) = &r {
                eprintln!("fixture notary error: {e:?}");
            }
            r
        });
        let key = hex::encode(Secp256k1Signer::new(&[1u8; 32])?.verifying_key().data);
        let subject="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA9UvpxYeFrMp/kGhLlthjiHwMSbrDTBJCljrM7CMcvuk=\n-----END PUBLIC KEY-----\n";
        let proof=tokio::time::timeout(Duration::from_secs(90),prove_with(json!({"notaryUrl":format!("ws://127.0.0.1:{port}/notarize"),"notaryKey":key,"publicKey":subject,"path":"/i/api/graphql/test/Viewer?test=true","headers":{"cookie":"secret-cookie"}}),SERVER_DOMAIN,("127.0.0.1",tls_port),roots.clone())).await??;
        notary_task.await??;
        tls_task.await?;
        let provider = CryptoProvider {
            cert: tlsn::verifier::ServerCertVerifier::new(&roots)?,
            ..Default::default()
        };
        let input = json!({"presentation":proof["presentation"],"trustedNotaryKeys":[key]});
        let out = verify_with(input.clone(), &provider)?;
        assert_eq!(out["subject"], subject);
        assert_eq!(out["server_name"], SERVER_DOMAIN);
        assert_eq!(
            out["transcript"]["sent"],
            "GET /i/api/graphql/test/Viewer?test=true HTTP/1.1\r\n"
        );
        assert!(!out.to_string().contains("secret-cookie"));
        assert!(!STANDARD
            .decode(proof["presentation"].as_str().unwrap())?
            .windows(13)
            .any(|b| b == b"secret-cookie"));
        // Production roots never accept the test certificate authority.
        assert!(verify(input.clone()).is_err());
        let mut unknown = input.clone();
        unknown["trustedNotaryKeys"] = json!([]);
        assert!(verify_with(unknown, &provider).is_err());
        let mut bytes = STANDARD.decode(proof["presentation"].as_str().unwrap())?;
        let pos = bytes
            .windows(subject.len())
            .position(|w| w == subject.as_bytes())
            .expect("bound public key in attestation");
        bytes[pos + 35] ^= 1;
        let mut tampered = input.clone();
        tampered["presentation"] = json!(STANDARD.encode(bytes));
        assert!(verify_with(tampered, &provider).is_err());
        let mut bytes = STANDARD.decode(proof["presentation"].as_str().unwrap())?;
        bytes.push(0);
        let mut trailing = input.clone();
        trailing["presentation"] = json!(STANDARD.encode(bytes));
        assert!(verify_with(trailing, &provider).is_err());
        eprintln!(
            "Portable fixture presentation bytes: {}",
            STANDARD
                .decode(proof["presentation"].as_str().unwrap())?
                .len()
        );
        Ok(())
    }
}
