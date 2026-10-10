use std::{
    fmt::{Debug, Formatter},
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bon::Builder;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncWriteExt, BufWriter},
    runtime::Runtime,
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

use crate::{Error, Fetched, FileResource, Fingerprint, Status, log};

#[derive(Builder)]
pub struct ParallelDownloader {
    #[builder(into)]
    install_dir: PathBuf,

    #[builder(into)]
    temp_dir: PathBuf,

    #[builder(default = 8)]
    concurrency: usize,

    #[builder(default = 3)]
    retries: usize,

    /// 0 uses one thread per CPU core
    #[builder(default = 0)]
    threads: usize,

    /// Bytes downloaded so far, files already up to date count as downloaded
    #[builder(default)]
    progress: Arc<AtomicU64>,

    #[builder(default)]
    cancellation_token: CancellationToken,
}

impl ParallelDownloader {
    pub fn run(&self, client: Client, files: Vec<FileResource>) -> Result<Vec<Fetched>, Error> {
        let runtime = match self.threads {
            0 => tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?,
            1 => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            n => tokio::runtime::Builder::new_multi_thread()
                .worker_threads(n)
                .enable_all()
                .build()?,
        };
        self.run_on(runtime, client, files)
    }

    #[inline(always)]
    pub fn run_on(
        &self,
        runtime: Runtime,
        client: Client,
        files: Vec<FileResource>,
    ) -> Result<Vec<Fetched>, Error> {
        runtime.block_on(self.run_inner(client, files))
    }

    async fn run_inner(
        &self,
        client: Client,
        files: Vec<FileResource>,
    ) -> Result<Vec<Fetched>, Error> {
        tokio::fs::create_dir_all(&self.temp_dir).await?;

        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();
        for file in files {
            let permit = match tokio::select! {
                _ = self.cancellation_token.cancelled() => None,
                permit = semaphore.clone().acquire_owned() => permit.ok(),
            } {
                Some(permit) => permit,
                None => break,
            };
            let client = client.clone();
            let install_dir = self.install_dir.clone();
            let temp_dir = self.temp_dir.clone();
            let retries = self.retries;
            let progress = self.progress.clone();
            let cancellation_token = self.cancellation_token.clone();

            let handle = tokio::spawn(async move {
                // Keep the permit alive for the duration of the task
                let _permit = permit;

                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        Ok(Fetched { status: Status::Cancelled, fingerprint: None })
                    }
                    result = file.fetch(&client, &install_dir, &temp_dir, retries, &progress) => {
                        if let Err(err) = &result {
                            log!("Failed to fetch {}: {}", file.path, err);
                            cancellation_token.cancel();
                        }
                        result
                    }
                }
            });

            handles.push(handle);
        }

        let mut fetched = Vec::with_capacity(handles.len());
        for handle in handles {
            fetched.push(
                handle
                    .await
                    .map_err(|err| Error::InternalError(err.to_string()))??,
            );
        }

        Ok(fetched)
    }

    pub fn progress(&self) -> Arc<AtomicU64> {
        self.progress.clone()
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }
}

impl FileResource {
    async fn fetch(
        &self,
        client: &Client,
        install_dir: &Path,
        temp_dir: &Path,
        retries: usize,
        progress: &AtomicU64,
    ) -> Result<Fetched, Error> {
        let size = self.size.max(0) as u64;

        let output_path = install_dir.join(&self.path);
        if let Ok((hash, fingerprint)) = sha256_file(output_path).await
            && hash.eq_ignore_ascii_case(&self.sum)
        {
            progress.fetch_add(size, Ordering::Relaxed);
            return Ok(Fetched {
                status: Status::Skipped,
                fingerprint: Some(fingerprint),
            });
        }

        let temp_path = temp_dir.join(&self.tmp);
        let mut reported = 0;
        let mut attempt = 0;
        let fingerprint = loop {
            match self
                .download(client, &temp_path, progress, &mut reported)
                .await
            {
                Ok(fingerprint) => break fingerprint,
                Err(err) if attempt < retries => {
                    attempt += 1;
                    log!("Retrying {} ({}/{}): {}", self.path, attempt, retries, err);
                    tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                }
                Err(err) => return Err(err),
            }
        };

        // Account for a size mismatch between the resource info and the actual file
        if size > reported {
            progress.fetch_add(size - reported, Ordering::Relaxed);
        }

        Ok(Fetched {
            status: Status::Downloaded,
            fingerprint: Some(fingerprint),
        })
    }

    async fn download(
        &self,
        client: &Client,
        temp_path: &Path,
        progress: &AtomicU64,
        reported: &mut u64,
    ) -> Result<Fingerprint, Error> {
        let mut response = client.get(&self.url).send().await?.error_for_status()?;

        let mut file = BufWriter::new(tokio::fs::File::create(temp_path).await?);
        let mut hasher = Sha256::new();
        let mut received = 0;
        while let Some(chunk) = response.chunk().await? {
            hasher.update(&chunk);
            file.write_all(&chunk).await?;

            // Skip bytes already reported by a previous attempt
            received += chunk.len() as u64;
            if received > *reported {
                progress.fetch_add(received - *reported, Ordering::Relaxed);
                *reported = received;
            }
        }
        file.flush().await?;
        // Close the file first, so its last write time does not change anymore
        drop(file.into_inner().into_std().await);
        let fingerprint = Fingerprint::of(&tokio::fs::metadata(temp_path).await?)?;

        let hash = format!("{:x}", hasher.finalize());
        if !hash.eq_ignore_ascii_case(&self.sum) {
            return Err(Error::ChecksumMismatch {
                path: self.path.clone(),
                expected: self.sum.clone(),
                actual: hash,
            });
        }

        Ok(fingerprint)
    }
}

pub fn sha256(path: &Path) -> io::Result<(String, Fingerprint)> {
    let mut file = std::fs::File::open(path)?;
    let fingerprint = Fingerprint::of(&file.metadata()?)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok((format!("{:x}", hasher.finalize()), fingerprint))
}

async fn sha256_file(path: PathBuf) -> Result<(String, Fingerprint), Error> {
    tokio::task::spawn_blocking(move || sha256(&path))
        .await
        .map_err(|err| Error::InternalError(err.to_string()))?
        .map_err(Error::from)
}

impl Debug for ParallelDownloader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelDownloader")
            .field("install_dir", &self.install_dir)
            .field("temp_dir", &self.temp_dir)
            .field("concurrency", &self.concurrency)
            .field("retries", &self.retries)
            .field("threads", &self.threads)
            .finish()
    }
}
