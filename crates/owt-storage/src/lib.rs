//! Objects in an S3-compatible bucket (Backblaze B2, Cloudflare R2, `MinIO`), with
//! client-side encryption through `owt-crypt`.
//!
//! * **Plain objects**: [`Storage::put`], [`Storage::get`], [`Storage::head`], and
//!   presigned URLs ([`Storage::presign_get`], [`Storage::presign_put`]) that let a
//!   browser read or write one object directly for a short while.
//! * **Encrypted objects**: [`Storage::put_sealed`] and [`Storage::upload_sealed`]
//!   encrypt in the app before anything leaves it; the bucket holds only ciphertext
//!   ([`sealed`] has the format). [`Storage::upload_sealed`] streams from a reader
//!   through a multipart upload, a chunk at a time, so a recording of any length
//!   takes bounded memory. [`Storage::get_sealed`] and [`Storage::download_sealed`]
//!   read them back, refusing any object altered, truncated or moved.
//! * **Verified deletion**: [`Storage::delete_verified`] deletes, then asks for the
//!   object again and fails unless the store answers that it is gone.
//!
//! **Versioned buckets.** Backblaze B2 keeps every version of an object by default
//! (Cloudflare R2 does not). On a versioned bucket a delete only hides the object: the
//! bytes stay recoverable by anyone holding the credentials, and a `HEAD` answering 404
//! does not mean they are gone, so [`Storage::delete_verified`] cannot tell. Add a
//! lifecycle rule that removes hidden versions (B2: "keep only the last version",
//! `daysFromHidingToDeleting: 1`) on any prefix that holds plaintext, such as
//! `incoming/`, or use a separate unversioned bucket for presigned uploads.
//!
//! **Interrupted uploads.** [`Storage::upload_sealed`] aborts its multipart upload when
//! it fails, but a dropped future (a client disconnect, a timeout, a cancelled task)
//! leaves an incomplete multipart upload that is billed and invisible to listing.
//! Give every bucket the lifecycle rule "abort incomplete multipart uploads after 1
//! day".
//!
//! A presigned URL moves bytes between the browser and the bucket without the app
//! seeing them, so it cannot encrypt them: an object uploaded that way is plaintext
//! until [`Storage::seal_uploaded`] encrypts it into its final key and deletes the
//! upload (see the README for the pattern and its trade-offs).

pub mod sealed;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path as ObjectPath;
use object_store::signer::{Method, Signer};
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, WriteMultipart};
use owt_crypt::{Crypt, CryptError, Field};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::sealed::{CHUNK, Chunks, Header, MAX_HEADER, PREFIX, TAG};

/// The longest a presigned URL lives.
pub const MAX_PRESIGN: Duration = Duration::from_hours(1);

/// The table and column a content key is sealed for, with the object's key as row.
pub const KEY_TABLE: &str = "owt_storage";
/// See [`KEY_TABLE`].
pub const KEY_COLUMN: &str = "object";

/// Why an operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The store.
    #[error("object storage: {0}")]
    Store(#[from] object_store::Error),
    /// Encryption.
    #[error(transparent)]
    Crypt(#[from] CryptError),
    /// Reading or writing the stream.
    #[error("object stream: {0}")]
    Io(#[from] std::io::Error),
    /// The object is not there.
    #[error("no object {0:?}")]
    NotFound(String),
    /// The object is still there after it was deleted.
    #[error("object {0:?} is still there after its deletion")]
    NotDeleted(String),
    /// The object is not an encrypted object, or was altered, truncated or moved.
    #[error("object {0:?} did not decrypt")]
    Refused(String),
    /// An encrypted operation on a storage without [`Storage::encrypted`].
    #[error("this storage has no encryption configured")]
    NoCrypt,
    /// A key that is not acceptable.
    #[error("not an acceptable object key: {0:?}")]
    BadKey(String),
    /// A configuration or argument that is not acceptable.
    #[error("{0}")]
    Invalid(String),
}

/// An S3-compatible bucket.
#[derive(Clone)]
pub struct S3Config {
    /// The endpoint (`https://s3.us-west-004.backblazeb2.com`,
    /// `https://<account>.r2.cloudflarestorage.com`, `http://127.0.0.1:9000`).
    pub endpoint: String,
    /// The bucket.
    pub bucket: String,
    /// The region (`us-west-004`; `auto` for R2).
    pub region: String,
    /// The access key id.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: String,
}

impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[redacted]")
            .finish()
    }
}

/// One bucket. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Storage {
    store: Arc<dyn ObjectStore>,
    signer: Option<Arc<AmazonS3>>,
    crypt: Option<Crypt>,
}

impl Storage {
    /// The bucket `config` names. Path-style requests, so any S3-compatible endpoint
    /// works; plain `http://` only for the loopback IP literals `127.0.0.1` and `[::1]`
    /// (a local `MinIO`), never for a name such as `localhost`, which resolution could
    /// point elsewhere. An endpoint that does not parse is [`StorageError::Invalid`].
    pub fn s3(config: &S3Config) -> Result<Self, StorageError> {
        let invalid = |why: &str| StorageError::Invalid(format!("S3 endpoint: {why}"));
        let endpoint = url::Url::parse(&config.endpoint).map_err(|_| invalid("not a URL"))?;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
            Some(url::Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
            _ => false,
        };
        match endpoint.scheme() {
            "https" => {}
            "http" if loopback => {}
            "http" => return Err(invalid("plain http is for 127.0.0.1 and [::1] only")),
            _ => return Err(invalid("the scheme is https")),
        }
        let s3 = Arc::new(
            AmazonS3Builder::new()
                .with_endpoint(&config.endpoint)
                .with_bucket_name(&config.bucket)
                .with_region(&config.region)
                .with_access_key_id(&config.access_key_id)
                .with_secret_access_key(&config.secret_access_key)
                .with_virtual_hosted_style_request(false)
                .with_allow_http(endpoint.scheme() == "http")
                .build()?,
        );
        Ok(Self {
            store: s3.clone(),
            signer: Some(s3),
            crypt: None,
        })
    }

    /// Any `object_store` store (an in-memory one in tests, a directory in
    /// development). It presigns nothing.
    #[must_use]
    pub fn from_store(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            signer: None,
            crypt: None,
        }
    }

    /// Encrypt sealed objects with `crypt`.
    #[must_use]
    pub fn encrypted(mut self, crypt: Crypt) -> Self {
        self.crypt = Some(crypt);
        self
    }

    /// Store `bytes` at `key` as they are.
    pub async fn put(&self, key: &str, bytes: Bytes) -> Result<(), StorageError> {
        self.store.put(&path(key)?, PutPayload::from(bytes)).await?;
        Ok(())
    }

    /// The bytes at `key`.
    pub async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        match self.store.get(&path(key)?).await {
            Ok(r) => Ok(r.bytes().await?),
            Err(object_store::Error::NotFound { .. }) => Err(StorageError::NotFound(key.into())),
            Err(e) => Err(e.into()),
        }
    }

    /// The size of the object at `key`, or `None` when there is none.
    pub async fn head(&self, key: &str) -> Result<Option<u64>, StorageError> {
        match self.store.head(&path(key)?).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete `key`, then ask for it again: fails unless the store answers that it is
    /// gone. A key already gone is deleted.
    ///
    /// **On a versioned bucket this does not erase the bytes.** Backblaze B2 is
    /// versioned by default (R2 is not): a delete only hides the object, a `HEAD` of 404
    /// is the hidden object's answer, and the bytes stay recoverable with the bucket's
    /// credentials until a lifecycle rule removes the hidden version (B2: "keep only the
    /// last version", `daysFromHidingToDeleting: 1`). With an object lock they stay
    /// until the lock expires. Set those rules to match what the app promises.
    pub async fn delete_verified(&self, key: &str) -> Result<(), StorageError> {
        let p = path(key)?;
        match self.store.delete(&p).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        match self.store.head(&p).await {
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Ok(_) => Err(StorageError::NotDeleted(key.into())),
            Err(e) => Err(e.into()),
        }
    }

    /// A URL that reads `key` for `ttl` (at most [`MAX_PRESIGN`]). `None` for a store
    /// that is not a bucket. An encrypted object read this way is ciphertext.
    pub async fn presign_get(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Result<Option<url::Url>, StorageError> {
        self.presign(Method::GET, key, ttl).await
    }

    /// A URL that writes `key` for `ttl` (at most [`MAX_PRESIGN`]): the browser `PUT`s
    /// the body to it. What it uploads is plaintext in the bucket; see
    /// [`Storage::seal_uploaded`]. The URL does not limit the size or type of the
    /// body, and stays valid until `ttl` ends even after the object is sealed and
    /// deleted, so whoever holds it can upload again: keep upload TTLs short (minutes),
    /// and use an unguessable key per upload.
    pub async fn presign_put(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Result<Option<url::Url>, StorageError> {
        self.presign(Method::PUT, key, ttl).await
    }

    async fn presign(
        &self,
        method: Method,
        key: &str,
        ttl: Duration,
    ) -> Result<Option<url::Url>, StorageError> {
        if ttl.is_zero() {
            return Err(StorageError::Invalid(
                "a presigned URL's TTL is not zero".into(),
            ));
        }
        let Some(signer) = &self.signer else {
            return Ok(None);
        };
        Ok(Some(
            signer
                .signed_url(method, &path(key)?, ttl.min(MAX_PRESIGN))
                .await?,
        ))
    }

    /// Encrypt `plaintext` for `scope` and store it at `key`.
    pub async fn put_sealed(
        &self,
        scope: &str,
        key: &str,
        plaintext: &[u8],
    ) -> Result<u64, StorageError> {
        self.upload_sealed(scope, key, plaintext).await
    }

    /// Encrypt what `reader` yields for `scope`, a chunk at a time, into a multipart
    /// upload at `key`. The plaintext's length. A failure aborts the upload, leaving
    /// no object.
    pub async fn upload_sealed<R>(
        &self,
        scope: &str,
        key: &str,
        mut reader: R,
    ) -> Result<u64, StorageError>
    where
        R: AsyncRead + Unpin + Send,
    {
        let crypt = self.crypt.as_ref().ok_or(StorageError::NoCrypt)?;
        let p = path(key)?;
        let mut content_key = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(&mut content_key[..]);
        let mut prefix = [0_u8; PREFIX];
        rand::rng().fill_bytes(&mut prefix);
        let sealed_key = crypt
            .encrypt(&key_field(scope, key), &content_key[..])
            .await?;
        let header = Header::new(sealed_key, prefix);
        let mut chunks = Chunks::new(&content_key, &header);

        let mut upload = WriteMultipart::new(self.store.put_multipart(&p).await?);
        upload.write(&header.bytes);
        let result = async {
            let mut total = 0_u64;
            let mut current = Zeroizing::new(read_chunk(&mut reader).await?);
            loop {
                // Read ahead one chunk: the last is marked as such.
                let next = Zeroizing::new(if current.len() == CHUNK {
                    read_chunk(&mut reader).await?
                } else {
                    Vec::new()
                });
                let last = next.is_empty();
                let sealed = chunks
                    .seal(&current, last)
                    .map_err(|_| StorageError::Refused(key.into()))?;
                total += current.len() as u64;
                upload.wait_for_capacity(4).await?;
                upload.put(Bytes::from(sealed));
                if last {
                    return Ok::<_, StorageError>(total);
                }
                current = next;
            }
        }
        .await;
        match result {
            Ok(total) => {
                // `finish` aborts the upload itself when completing it fails.
                upload.finish().await?;
                Ok(total)
            }
            Err(e) => {
                // Best effort: if the store is unreachable the parts are left for the
                // bucket's abort-incomplete-uploads rule.
                let _ = upload.abort().await;
                Err(e)
            }
        }
    }

    /// The decrypted object at `key`, sealed for `scope`.
    pub async fn get_sealed(
        &self,
        scope: &str,
        key: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let mut out = Zeroizing::new(Vec::new());
        self.download_sealed(scope, key, &mut *out).await?;
        Ok(out)
    }

    /// Decrypt the object at `key`, sealed for `scope`, into `writer` a chunk at a
    /// time. A chunk is written only once it authenticates, but a failure part way
    /// leaves the chunks before it written: write to a temporary place, or discard
    /// what was written on error. The plaintext's length.
    pub async fn download_sealed<W>(
        &self,
        scope: &str,
        key: &str,
        mut writer: W,
    ) -> Result<u64, StorageError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let crypt = self.crypt.as_ref().ok_or(StorageError::NoCrypt)?;
        let refused = || StorageError::Refused(key.into());
        let mut stream = match self.store.get(&path(key)?).await {
            Ok(r) => r.into_stream(),
            Err(object_store::Error::NotFound { .. }) => {
                return Err(StorageError::NotFound(key.into()));
            }
            Err(e) => return Err(e.into()),
        };
        let mut buf: Vec<u8> = Vec::new();
        let header = loop {
            if let Some(h) = Header::parse(&buf).map_err(|_| refused())? {
                break h;
            }
            if buf.len() > MAX_HEADER {
                return Err(refused());
            }
            match stream.next().await {
                Some(bytes) => buf.extend_from_slice(&bytes?),
                None => return Err(refused()),
            }
        };
        buf.drain(..header.bytes.len());
        let content_key = crypt
            .decrypt(&key_field(scope, key), &header.sealed_key)
            .await?;
        if content_key.len() != 32 {
            return Err(refused());
        }
        let mut raw = Zeroizing::new([0_u8; 32]);
        raw.copy_from_slice(&content_key);
        let content_key = raw;
        let mut chunks = Chunks::new(&content_key, &header);
        let sealed_chunk = header.chunk + TAG;
        let mut total = 0_u64;
        let mut ended = false;
        loop {
            // A full chunk with more after it is not the last; whatever remains at the
            // end of the stream is.
            while buf.len() <= sealed_chunk && !ended {
                match stream.next().await {
                    Some(bytes) => buf.extend_from_slice(&bytes?),
                    None => ended = true,
                }
            }
            let last = ended && buf.len() <= sealed_chunk;
            let take = if last { buf.len() } else { sealed_chunk };
            if last && take < TAG {
                return Err(refused());
            }
            let plain = chunks.open(&buf[..take], last).map_err(|_| refused())?;
            buf.drain(..take);
            writer.write_all(&plain).await?;
            total += plain.len() as u64;
            if last {
                writer.flush().await?;
                return Ok(total);
            }
        }
    }

    /// Encrypt the plaintext object a presigned upload left at `from` into `to` for
    /// `scope`, then delete `from`, verified. The plaintext's length. `from` and `to`
    /// must differ ([`StorageError::BadKey`]). On a versioned bucket the delete only
    /// hides the upload (see the module docs), and the presigned URL that wrote it can
    /// write again until its TTL ends: seal after the URL has expired.
    pub async fn seal_uploaded(
        &self,
        scope: &str,
        from: &str,
        to: &str,
    ) -> Result<u64, StorageError> {
        if from == to {
            return Err(StorageError::BadKey(from.into()));
        }
        let source = match self.store.get(&path(from)?).await {
            Ok(r) => r.into_stream(),
            Err(object_store::Error::NotFound { .. }) => {
                return Err(StorageError::NotFound(from.into()));
            }
            Err(e) => return Err(e.into()),
        };
        let reader =
            tokio_util::io::StreamReader::new(source.map(|r| r.map_err(std::io::Error::other)));
        let n = self.upload_sealed(scope, to, reader).await?;
        self.delete_verified(from).await?;
        Ok(n)
    }
}

impl Storage {
    /// Rewrite the object at `key`, sealed for `scope`, under `scope`'s current data
    /// key: the job that lets an old data-key version be retired.
    ///
    /// **Why an object must be rewritten.** The sealed content key is part of the
    /// header, which is every chunk's associated data, and it is bound to the object's
    /// key. Re-wrapping the content key alone would change the header and so every
    /// chunk, and a copy to a temporary key would not open at the original key. So
    /// this streams [`Storage::download_sealed`] into [`Storage::upload_sealed`] at the
    /// same key, with a fresh content key. The upload replaces the object only when it
    /// completes, and it completes only after the download authenticated the last
    /// chunk and the lengths agree; any failure aborts it and leaves the original.
    /// Readers see the old version until the replacement lands (a short window, which
    /// is acceptable), and on a versioned bucket the old version stays recoverable
    /// until the lifecycle rules remove it (see the module docs). Bounded memory. The
    /// plaintext's length.
    pub async fn reencrypt(&self, scope: &str, key: &str) -> Result<u64, StorageError> {
        let (writer, reader) = tokio::io::duplex(CHUNK);
        let failed = Arc::new(AtomicBool::new(false));
        let download = {
            let failed = failed.clone();
            async move {
                let r = self.download_sealed(scope, key, writer).await;
                // Before the pipe is seen to end: an upload must not finish a short
                // object because the download died.
                if r.is_err() {
                    failed.store(true, Ordering::SeqCst);
                }
                r
            }
        };
        let upload = self.upload_sealed(
            scope,
            key,
            FailingEof {
                inner: reader,
                failed,
            },
        );
        let (downloaded, uploaded) = tokio::join!(download, upload);
        let downloaded = downloaded?;
        let uploaded = uploaded?;
        if downloaded != uploaded {
            return Err(StorageError::Refused(key.into()));
        }
        Ok(uploaded)
    }
}

/// A reader whose end is an error when `failed` is set: the sender gave up, and the
/// bytes so far are not the whole.
struct FailingEof {
    inner: tokio::io::DuplexStream,
    failed: Arc<AtomicBool>,
}

impl AsyncRead for FailingEof {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, std::task::Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && self.failed.load(Ordering::SeqCst)
        {
            return std::task::Poll::Ready(Err(std::io::Error::other(
                "the download failed before its end",
            )));
        }
        polled
    }
}

/// Read up to a chunk from `reader`, short only at its end.
async fn read_chunk<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0_u8; CHUNK];
    let mut filled = 0;
    while filled < CHUNK {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

fn key_field<'a>(scope: &'a str, key: &'a str) -> Field<'a> {
    Field::new(scope, KEY_TABLE, KEY_COLUMN, key)
}

/// An object key: 1 to 1024 bytes, no control characters, no empty, `.` or `..`
/// segment, no leading `/`.
fn path(key: &str) -> Result<ObjectPath, StorageError> {
    let bad = key.is_empty()
        || key.len() > 1024
        || key.chars().any(char::is_control)
        || key
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        return Err(StorageError::BadKey(key.into()));
    }
    ObjectPath::parse(key).map_err(|_| StorageError::BadKey(key.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked() {
        for ok in ["a", "recordings/2026/10/abc.webm", "t-1/x_y.z"] {
            assert!(path(ok).is_ok(), "{ok}");
        }
        for bad in ["", "/a", "a/", "a//b", "a/../b", "./a", "a\nb"] {
            assert!(path(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn presigned_urls_are_signed_and_short_lived() {
        let s = Storage::s3(&S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "media".into(),
            region: "us-east-1".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        })
        .unwrap();
        let get = s
            .presign_get("a/b.webm", Duration::from_hours(48))
            .await
            .unwrap()
            .unwrap();
        let q = get.query().unwrap();
        assert!(get.path().ends_with("/media/a/b.webm"), "{get}");
        assert!(q.contains("X-Amz-Signature="));
        assert!(q.contains("X-Amz-Expires=3600"), "capped at an hour: {q}");
        assert!(!q.contains("wJalrXUtnFEMI"));
        let put = s
            .presign_put("a/b.webm", Duration::from_mins(5))
            .await
            .unwrap()
            .unwrap();
        assert!(put.query().unwrap().contains("X-Amz-Expires=300"));
        let mem = Storage::from_store(Arc::new(object_store::memory::InMemory::new()));
        assert!(
            mem.presign_get("a", Duration::from_mins(1))
                .await
                .unwrap()
                .is_none()
        );
    }

    fn config(endpoint: &str) -> S3Config {
        S3Config {
            endpoint: endpoint.into(),
            bucket: "media".into(),
            region: "us-east-1".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        }
    }

    #[test]
    fn the_secret_does_not_print() {
        let shown = format!("{:?}", config("https://s3.example.com"));
        assert!(
            shown.contains("secret_access_key: \"[redacted]\""),
            "{shown}"
        );
        assert!(!shown.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn plain_http_is_for_loopback_ip_literals_only() {
        for ok in [
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
            "https://s3.example.com",
            "https://localhost:9000",
        ] {
            assert!(Storage::s3(&config(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "http://localhost:9000",
            "http://10.0.0.5:9000",
            "http://s3.example.com",
            "http://127.0.0.2:9000",
            "ftp://127.0.0.1",
            "not a url",
        ] {
            assert!(
                matches!(Storage::s3(&config(bad)), Err(StorageError::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn a_zero_ttl_is_refused() {
        let s = Storage::s3(&config("http://127.0.0.1:9000")).unwrap();
        assert!(matches!(
            s.presign_put("a", Duration::ZERO).await,
            Err(StorageError::Invalid(_))
        ));
        assert!(matches!(
            s.presign_get("a", Duration::ZERO).await,
            Err(StorageError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn sealing_an_upload_onto_itself_is_refused() {
        let s = Storage::from_store(Arc::new(object_store::memory::InMemory::new()));
        s.put("incoming/a", Bytes::from_static(b"plain"))
            .await
            .unwrap();
        assert!(matches!(
            s.seal_uploaded("t", "incoming/a", "incoming/a").await,
            Err(StorageError::BadKey(_))
        ));
        assert_eq!(&s.get("incoming/a").await.unwrap()[..], b"plain");
    }
}
