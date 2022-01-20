// Implementation of https://datatracker.ietf.org/doc/html/rfc7489
use slog::warn;
use std::collections::HashMap;
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;

#[macro_use]
extern crate quick_error;

mod dns;
mod errors;
mod parser;
mod policy;
mod result;

pub use errors::DMARCError;
pub use policy::{Policy, ReceiverAction};
pub use result::DMARCResult;

const DNS_SUBDOMAIN: &str = "_dmarc";

/// Since the SPF crate we are using (visaspf) doesn't expose a result struct
/// with the domain that it used, we'll use our own.
pub struct SPFResult {
    pub domain_used: String,
    pub value: String,
}

/// Context needed to run a DMARC policy
pub struct PolicyContext<'a> {
    /// Result of the DKIM verification
    pub dkim_result: cfdkim::DKIMResult,
    /// Result of the SPF verification
    pub spf_result: SPFResult,
    /// RFC5322.From's domain
    pub from_domain: &'a str,
    /// Logger for debugging
    pub logger: &'a slog::Logger,
}

/// Load the DMARC policy for the domain
pub async fn load_policy<'a>(
    logger: &'a slog::Logger,
    from_domain: &'a str,
) -> Result<Option<policy::Policy>, DMARCError> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|err| {
        DMARCError::UnknownInternalError(format!("failed to create DNS resolver: {}", err))
    })?;
    let resolver = dns::from_tokio_resolver(resolver);

    load_policy_with_resolver(resolver, logger, from_domain).await
}

// https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3
async fn load_policy_with_resolver<'a>(
    resolver: Arc<dyn dns::Lookup>,
    logger: &'a slog::Logger,
    from_domain: &'a str,
) -> Result<Option<policy::Policy>, DMARCError> {
    macro_rules! load {
        ($name:expr, $is_root:expr) => {
            for record in resolver.lookup_txt(&$name).await? {
                if record.starts_with("v=") {
                    match parse_policy(&record, $is_root) {
                        Ok(policy) => return Ok(Some(policy)),
                        Err(err) => warn!(logger, "DMARC policy parse error: {}", err),
                    }
                }
            }
        };
    }

    // Search DMARC policy at the current domain
    load!(format!("{}.{}", DNS_SUBDOMAIN, from_domain), false);

    // No policy was found, if the domain was a subdomain try at the root domain
    if let Some(root) = dns::get_root_domain_name(from_domain) {
        load!(format!("{}.{}", DNS_SUBDOMAIN, root), true);
    }

    // Finally, if no policy was found return nothing
    Ok(None)
}

/// Parse a DMARC policy
///
/// If the policy wasn't found at the current domain but was found at the root
/// domain `is_root` must be true. And if the `sp` tag was provided it will be
/// set to the policy's action, otherwise the `p` tag will be used.
///
/// For non-root domains, the policy's action is set to the `p` tag.
fn parse_policy(record: &str, is_root: bool) -> Result<policy::Policy, DMARCError> {
    let tags = parser::parse(record)?;

    let mut tags_map = HashMap::new();
    for tag in &tags {
        tags_map.insert(tag.name.clone(), tag.value.clone());
    }

    // Check version
    {
        let v = tags_map
            .get("v")
            .ok_or(DMARCError::MissingRequiredTag("v"))?;
        if v != "DMARC1" {
            return Err(DMARCError::IncompatibleVersion(v.to_owned()));
        }
    }

    let action = if is_root {
        let p = tags_map
            .get("p")
            .ok_or(DMARCError::MissingRequiredTag("p"))?;

        if let Some(sp) = tags_map.get("sp") {
            sp
        } else {
            p
        }
    } else {
        tags_map
            .get("p")
            .ok_or(DMARCError::MissingRequiredTag("p"))?
    };

    let action = parser::parse_receiver_action(action)?;

    let mut policy = policy::Policy::new(action);

    if let Some(v) = tags_map.get("adkim") {
        policy.adkim = parser::parse_alignement_mode(v);
    }
    if let Some(v) = tags_map.get("aspf") {
        policy.aspf = parser::parse_alignement_mode(v);
    }
    if let Some(v) = tags_map.get("pct") {
        policy.pct = parser::parse_percentage(v);
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::BoxFuture;
    use policy::{Alignement, Policy, ReceiverAction};
    use std::collections::HashMap;

    #[test]
    fn test_parse_policy() {
        assert_eq!(
            parse_policy(
                "v=DMARC1;p=none;sp=quarantine;pct=67;rua=mailto:dmarcreports@example.com;",
                false
            )
            .unwrap(),
            Policy {
                adkim: Alignement::Relaxed,
                aspf: Alignement::Relaxed,
                pct: 67,
                action: ReceiverAction::None
            }
        );
    }

    #[test]
    fn test_parse_policy_invalid_version() {
        assert_eq!(
            parse_policy("v=DMARC6", false).unwrap_err(),
            DMARCError::IncompatibleVersion("DMARC6".to_owned())
        );
    }

    #[test]
    fn test_parse_policy_require_tags() {
        assert_eq!(
            parse_policy("p=none;", false).unwrap_err(),
            DMARCError::MissingRequiredTag("v")
        );
        assert_eq!(
            parse_policy("v=DMARC1;", false).unwrap_err(),
            DMARCError::MissingRequiredTag("p")
        );
    }

    #[test]
    fn test_parse_policy_invalid_pct() {
        let policy = parse_policy("v=DMARC1;p=none;pct=77777;", false).unwrap();
        assert_eq!(policy.pct, 100);
    }

    #[test]
    fn test_parse_policy_invalid_alignement_mode() {
        let policy = parse_policy("v=DMARC1;p=none;adkim=hein", false).unwrap();
        assert_eq!(policy.adkim, Alignement::Relaxed);
    }

    #[test]
    fn test_parse_policy_action_inherit_from_root() {
        let policy = parse_policy("v=DMARC1;p=none;sp=reject", true).unwrap();
        assert_eq!(policy.action, ReceiverAction::Reject);
    }

    macro_rules! map {
        { $($key:expr => $value:expr),+ } => {
             {
                 let mut m = ::std::collections::HashMap::new();
                 $(
                     m.insert($key, $value);
                 )+
                     m
             }
         };
    }

    fn test_resolver(db: HashMap<&'static str, &'static str>) -> Arc<dyn dns::Lookup> {
        struct TestResolver {
            db: HashMap<&'static str, &'static str>,
        }
        impl dns::Lookup for TestResolver {
            fn lookup_txt<'a>(
                &'a self,
                name: &'a str,
            ) -> BoxFuture<'a, Result<Vec<String>, DMARCError>> {
                let res = if let Some(value) = self.db.get(name) {
                    vec![value.to_string()]
                } else {
                    vec![]
                };
                Box::pin(async move { Ok(res) })
            }
        }
        Arc::new(TestResolver { db })
    }

    #[tokio::test]
    async fn test_load_policy() {
        let resolver = test_resolver(map! {
            "_dmarc.example.com" => "v=DMARC1; p=none; pct=13;",
            "_dmarc.sub.example.com" => "v=DMARC1; p=none; pct=26;"
        });
        let logger = slog::Logger::root(slog::Discard, slog::o!());

        let policy = load_policy_with_resolver(Arc::clone(&resolver), &logger, "example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.pct, 13);

        let policy = load_policy_with_resolver(Arc::clone(&resolver), &logger, "sub.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.pct, 26);
    }

    #[tokio::test]
    async fn test_load_policy_subdomain_no_policy() {
        let resolver = test_resolver(map! {
            "_dmarc.example.com" => "v=DMARC1; p=none; pct=13;"
        });
        let logger = slog::Logger::root(slog::Discard, slog::o!());

        let policy = load_policy_with_resolver(Arc::clone(&resolver), &logger, "sub.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.pct, 13);
    }
}
