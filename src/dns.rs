///! Module to abstract DNS operations
use crate::DMARCError;
use futures::future::BoxFuture;
use std::sync::Arc;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::TokioAsyncResolver;

/// A trait for entities that perform DNS resolution.
pub trait Lookup: Sync + Send {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DMARCError>>;
}

// Technically we should be able to implemement Lookup for TokioAsyncResolver
// directly but it's failing for some reason.
struct TokioAsyncResolverWrapper {
    inner: TokioAsyncResolver,
}
impl Lookup for TokioAsyncResolverWrapper {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DMARCError>> {
        Box::pin(async move {
            let res = self.inner.txt_lookup(name).await;
            match res {
                Ok(res) => {
                    let records: Vec<String> = res
                        .into_iter()
                        .map(|txt| {
                            txt.iter()
                                .map(|data| String::from_utf8_lossy(data))
                                .collect()
                        })
                        .collect();
                    Ok(records)
                }
                Err(err) => match err.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => Ok(vec![]),
                    _ => Err(DMARCError::UnknownInternalError(format!(
                        "failed to query DNS: {}",
                        err
                    ))),
                },
            }
        })
    }
}

pub fn from_tokio_resolver(resolver: TokioAsyncResolver) -> Arc<dyn Lookup> {
    Arc::new(TokioAsyncResolverWrapper { inner: resolver })
}

// https://datatracker.ietf.org/doc/html/rfc7489#section-3.2
pub(crate) fn get_root_domain_name(domain: &str) -> Option<String> {
    if let Ok(domain) = addr::parse_domain_name(domain) {
        domain.root().map(|d| d.to_owned())
    } else {
        None
    }
}
