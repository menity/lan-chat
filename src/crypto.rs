use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroize;

use crate::protocol::{MAX_CIPHERTEXT_FRAME, MAX_PLAINTEXT_FRAME};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_HANDSHAKE_FRAME: usize = 4096;

pub struct NoiseKeypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl Drop for NoiseKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
        self.public.zeroize();
    }
}

pub fn generate_keypair() -> Result<NoiseKeypair> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise pattern")?;
    let pair = Builder::new(params)
        .generate_keypair()
        .context("failed to generate Noise keypair")?;
    Ok(NoiseKeypair {
        private: pair.private,
        public: pair.public,
    })
}

pub fn load_or_create_keypair(path: &Path) -> Result<NoiseKeypair> {
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            let mut version = [0u8; 1];
            file.read_exact(&mut version)
                .context("gateway Noise key file is truncated")?;
            if version[0] != 1 {
                bail!("unsupported gateway Noise key file version");
            }
            let mut lengths = [0u8; 2];
            file.read_exact(&mut lengths)
                .context("gateway Noise key file is truncated")?;
            let private_length = usize::from(lengths[0]);
            let public_length = usize::from(lengths[1]);
            if private_length != 32 || public_length != 32 {
                bail!("gateway Noise key file contains invalid key lengths");
            }
            let mut private = vec![0u8; private_length];
            let mut public = vec![0u8; public_length];
            file.read_exact(&mut private)
                .context("gateway Noise private key is truncated")?;
            file.read_exact(&mut public)
                .context("gateway Noise public key is truncated")?;
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 {
                bail!("gateway Noise key file has trailing data");
            }
            Ok(NoiseKeypair { private, public })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let keypair = generate_keypair()?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .context("failed to create the gateway Noise key file")?;
            file.write_all(&[1, keypair.private.len() as u8, keypair.public.len() as u8])?;
            file.write_all(&keypair.private)?;
            file.write_all(&keypair.public)?;
            file.sync_all()?;
            Ok(keypair)
        }
        Err(error) => Err(error).context("failed to open the gateway Noise key file"),
    }
}

pub fn public_key_fingerprint(public_key: &[u8]) -> String {
    let digest = blake3::hash(public_key);
    digest.as_bytes()[..12]
        .chunks(2)
        .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
        .collect::<Vec<_>>()
        .join(":")
}

pub async fn client_handshake(
    stream: &mut TcpStream,
    local_keypair: &NoiseKeypair,
) -> Result<(TransportState, String)> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise pattern")?;
    let mut handshake = Builder::new(params)
        .local_private_key(&local_keypair.private)
        .context("invalid local Noise private key")?
        .build_initiator()
        .context("failed to initialize Noise initiator")?;

    send_handshake_message(stream, &mut handshake).await?;
    receive_handshake_message(stream, &mut handshake).await?;
    send_handshake_message(stream, &mut handshake).await?;

    let remote_key = handshake
        .get_remote_static()
        .context("server did not provide a Noise static key")?
        .to_vec();
    let fingerprint = public_key_fingerprint(&remote_key);
    let transport = handshake
        .into_transport_mode()
        .context("failed to enter encrypted transport mode")?;
    Ok((transport, fingerprint))
}

pub async fn server_handshake(
    stream: &mut TcpStream,
    local_keypair: &NoiseKeypair,
) -> Result<TransportState> {
    Ok(server_handshake_with_remote(stream, local_keypair).await?.0)
}

pub async fn server_handshake_with_remote(
    stream: &mut TcpStream,
    local_keypair: &NoiseKeypair,
) -> Result<(TransportState, String)> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise pattern")?;
    let mut handshake = Builder::new(params)
        .local_private_key(&local_keypair.private)
        .context("invalid local Noise private key")?
        .build_responder()
        .context("failed to initialize Noise responder")?;

    receive_handshake_message(stream, &mut handshake).await?;
    send_handshake_message(stream, &mut handshake).await?;
    receive_handshake_message(stream, &mut handshake).await?;

    let remote_key = handshake
        .get_remote_static()
        .context("client did not provide a Noise static key")?
        .to_vec();
    let fingerprint = public_key_fingerprint(&remote_key);
    let transport = handshake
        .into_transport_mode()
        .context("failed to enter encrypted transport mode")?;
    Ok((transport, fingerprint))
}

async fn send_handshake_message(
    stream: &mut TcpStream,
    handshake: &mut HandshakeState,
) -> Result<()> {
    let mut output = vec![0u8; MAX_HANDSHAKE_FRAME];
    let written = handshake
        .write_message(&[], &mut output)
        .context("failed to create Noise handshake message")?;
    write_raw_frame(stream, &output[..written], MAX_HANDSHAKE_FRAME).await
}

async fn receive_handshake_message(
    stream: &mut TcpStream,
    handshake: &mut HandshakeState,
) -> Result<()> {
    let input = read_raw_frame(stream, MAX_HANDSHAKE_FRAME).await?;
    let mut output = vec![0u8; MAX_HANDSHAKE_FRAME];
    handshake
        .read_message(&input, &mut output)
        .context("invalid Noise handshake message")?;
    Ok(())
}

async fn write_raw_frame<W>(writer: &mut W, payload: &[u8], maximum: usize) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() || payload.len() > maximum || payload.len() > u16::MAX as usize {
        bail!("invalid frame size: {}", payload.len());
    }
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_raw_frame<R>(reader: &mut R, maximum: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u16().await? as usize;
    if length == 0 || length > maximum {
        bail!("invalid incoming frame size: {length}");
    }
    let mut frame = vec![0u8; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

pub struct SecureReader<R> {
    reader: R,
    state: Arc<Mutex<TransportState>>,
}

pub struct SecureWriter<W> {
    writer: W,
    state: Arc<Mutex<TransportState>>,
}

pub fn split_secure_stream(
    stream: TcpStream,
    state: TransportState,
) -> (
    SecureReader<tokio::net::tcp::OwnedReadHalf>,
    SecureWriter<tokio::net::tcp::OwnedWriteHalf>,
) {
    let state = Arc::new(Mutex::new(state));
    let (reader, writer) = stream.into_split();
    (
        SecureReader {
            reader,
            state: Arc::clone(&state),
        },
        SecureWriter { writer, state },
    )
}

impl<R> SecureReader<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn read_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        let encrypted = read_raw_frame(&mut self.reader, MAX_CIPHERTEXT_FRAME).await?;
        let mut plaintext = vec![0u8; MAX_PLAINTEXT_FRAME];
        let plaintext_len = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Noise transport lock was poisoned"))?
            .read_message(&encrypted, &mut plaintext)
            .context("failed to decrypt incoming frame")?;
        serde_json::from_slice(&plaintext[..plaintext_len])
            .context("incoming encrypted frame contains invalid JSON")
    }
}

impl<W> SecureWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub async fn write_json<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let plaintext =
            serde_json::to_vec(value).context("failed to serialize outgoing message")?;
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_FRAME {
            bail!("outgoing message exceeds the protocol frame limit");
        }

        let encrypted = {
            let mut output = vec![0u8; MAX_CIPHERTEXT_FRAME];
            let written = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("Noise transport lock was poisoned"))?
                .write_message(&plaintext, &mut output)
                .context("failed to encrypt outgoing frame")?;
            output.truncate(written);
            output
        };

        write_raw_frame(&mut self.writer, &encrypted, MAX_CIPHERTEXT_FRAME).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_short_and_stable() {
        let key = [7u8; 32];
        let first = public_key_fingerprint(&key);
        assert_eq!(first, public_key_fingerprint(&key));
        assert_eq!(first.len(), 29);
    }
}
