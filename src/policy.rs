use rand::distributions::Bernoulli;
use rand::distributions::Distribution;
use slog::debug;
use std::default::Default;

use crate::{dns, DMARCResult, PolicyContext, SPFResult};

#[derive(Debug, PartialEq, Clone)]
pub enum Alignement {
    Relaxed,
    Strict,
}
// Since deriving `Default` on enums is experimental we'll need to implement
// it ourselves for the time being
impl Default for Alignement {
    fn default() -> Self {
        Self::Relaxed
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ReceiverAction {
    None,
    Quarantine,
    Reject,
}
impl ReceiverAction {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
/// DMARC policy
pub struct Policy {
    /// DKIM Identifier Alignment mode
    pub adkim: Alignement,
    /// SPF Identifier Alignment mode
    pub aspf: Alignement,
    /// Requested Mail Receiver policy (includes subdomain)
    pub action: ReceiverAction,
    /// Percentage of messages to which the DMARC policy is to be applied
    pub pct: usize,
}

impl Policy {
    /// Creates a Policy with default as specified in
    /// https://datatracker.ietf.org/doc/html/rfc7489#section-6.3
    pub fn new(action: ReceiverAction) -> Self {
        Policy {
            adkim: Alignement::Relaxed,
            aspf: Alignement::Relaxed,
            pct: 100,
            action,
        }
    }

    /// Based on the `pct` tag, determine if the DMARC policy should be applied
    pub fn should_apply(&self) -> bool {
        let d = match Bernoulli::new(self.pct as f64 / 100.0) {
            Ok(d) => d,
            Err(_) => {
                // an invalid probability throws an error, it's unlikely to happen
                // given that we validate the value before.
                // Return true like rcpt = 100.
                return true;
            }
        };
        d.sample(&mut rand::thread_rng())
    }

    // https://datatracker.ietf.org/doc/html/rfc7489#section-3.1
    pub fn check_spf_alignment(&self, from_domain: &str, spf_result: &SPFResult) -> bool {
        match self.aspf {
            Alignement::Relaxed => {
                let root_from = dns::get_root_domain_name(from_domain);
                let root_used_domain = dns::get_root_domain_name(&spf_result.domain_used);

                if root_from == root_used_domain {
                    return true;
                }
            }
            Alignement::Strict => {
                if from_domain == spf_result.domain_used {
                    return true;
                }
            }
        }
        false
    }

    pub fn check_dkim_alignment<'a>(
        &self,
        from_domain: &str,
        dkim_result: &cfdkim::DKIMResult,
    ) -> bool {
        match self.adkim {
            Alignement::Relaxed => {
                let root_from = dns::get_root_domain_name(from_domain);
                let root_used_domain = dns::get_root_domain_name(&dkim_result.domain_used());

                if root_from == root_used_domain {
                    return true;
                }
            }
            Alignement::Strict => {
                if from_domain == dkim_result.domain_used() {
                    return true;
                }
            }
        }
        false
    }

    /// Apply a DMARC policy as specified in
    /// https://datatracker.ietf.org/doc/html/rfc7489#section-6.6
    ///
    /// The context provides the information (steps 1, 3 and 4 from
    /// https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.2)
    ///
    /// Checks authentication mechanisms result
    /// https://datatracker.ietf.org/doc/html/rfc7489#section-4.2
    pub fn apply<'a>(&self, ctx: &PolicyContext<'a>) -> DMARCResult {
        if !self.should_apply() {
            debug!(ctx.logger, "should not apply DMARC policy");
            return DMARCResult::neutral(self.clone());
        }

        // If DKIM is aligned, check its result. If pass, DMARC passes
        if self.check_dkim_alignment(&ctx.from_domain, &ctx.dkim_result) {
            let res = ctx.dkim_result.summary();
            if res == "pass" {
                return DMARCResult::pass(self.clone());
            }

            debug!(ctx.logger, "dkim aligned but result {}", res);
        }

        // If PSF is aligned, check its result. If pass, DMARC passes
        if self.check_spf_alignment(&ctx.from_domain, &ctx.spf_result) {
            let res = &ctx.spf_result.value;
            if res == "pass" {
                return DMARCResult::pass(self.clone());
            }

            debug!(ctx.logger, "spf aligned but result {}", res);
        }

        // No authentication mechanisms were aligned and passes, DMARC fails
        DMARCResult::fail(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_apply() {
        let mut policy = Policy::new(ReceiverAction::Reject);

        policy.pct = 0;
        assert_eq!(policy.should_apply(), false);

        policy.pct = 100;
        assert_eq!(policy.should_apply(), true);
    }

    #[test]
    fn test_apply() {
        let policy = Policy::new(ReceiverAction::Reject);
        let from_domain = "a.com";
        let logger = slog::Logger::root(slog::Discard, slog::o!());

        // SPF & DKIM pass
        {
            let ctx = PolicyContext {
                from_domain,
                logger: &logger,
                dkim_result: cfdkim::DKIMResult::pass("a.com".to_owned()),
                spf_result: SPFResult {
                    domain_used: "a.com".to_string(),
                    value: "pass".to_string(),
                },
            };
            assert_eq!(policy.apply(&ctx).to_str(), "pass");
        }

        // SPF & DKIM pass but not aligned
        {
            let ctx = PolicyContext {
                from_domain,
                logger: &logger,
                dkim_result: cfdkim::DKIMResult::pass("b.com".to_owned()),
                spf_result: SPFResult {
                    domain_used: "b.com".to_string(),
                    value: "pass".to_string(),
                },
            };
            assert_eq!(policy.apply(&ctx).to_str(), "fail");
        }

        // SPF pass
        {
            let ctx = PolicyContext {
                from_domain,
                logger: &logger,
                dkim_result: cfdkim::DKIMResult::neutral("a.com".to_owned()),
                spf_result: SPFResult {
                    domain_used: "a.com".to_string(),
                    value: "pass".to_string(),
                },
            };
            assert_eq!(policy.apply(&ctx).to_str(), "pass");
        }

        // DKIM pass
        {
            let ctx = PolicyContext {
                from_domain,
                logger: &logger,
                dkim_result: cfdkim::DKIMResult::pass("a.com".to_owned()),
                spf_result: SPFResult {
                    domain_used: "a.com".to_string(),
                    value: "fail".to_string(),
                },
            };
            assert_eq!(policy.apply(&ctx).to_str(), "pass");
        }

        // non pass
        {
            let ctx = PolicyContext {
                from_domain,
                logger: &logger,
                dkim_result: cfdkim::DKIMResult::neutral("a.com".to_owned()),
                spf_result: SPFResult {
                    domain_used: "a.com".to_string(),
                    value: "fail".to_string(),
                },
            };
            assert_eq!(policy.apply(&ctx).to_str(), "fail");
        }
    }

    #[test]
    fn test_check_alignement_spf_strict() {
        let mut policy = Policy::new(ReceiverAction::Reject);
        policy.aspf = Alignement::Strict;

        let from_domain = "a.com";

        let spf_result = SPFResult {
            domain_used: "notfy.a.com".to_string(),
            value: "-".to_string(),
        };
        assert_eq!(policy.check_spf_alignment(from_domain, &spf_result), false);

        let spf_result = SPFResult {
            domain_used: "a.com".to_string(),
            value: "-".to_string(),
        };
        assert_eq!(policy.check_spf_alignment(from_domain, &spf_result), true);

        let spf_result = SPFResult {
            domain_used: "cc.com".to_string(),
            value: "-".to_string(),
        };
        assert_eq!(policy.check_spf_alignment(from_domain, &spf_result), false);
    }

    #[test]
    fn test_check_alignement_spf_relaxed() {
        let mut policy = Policy::new(ReceiverAction::Reject);
        policy.aspf = Alignement::Relaxed;

        let from_domain = "a.com";

        let spf_result = SPFResult {
            domain_used: "notfy.a.com".to_string(),
            value: "-".to_string(),
        };
        assert_eq!(policy.check_spf_alignment(from_domain, &spf_result), true);

        let spf_result = SPFResult {
            domain_used: "cc.com".to_string(),
            value: "-".to_string(),
        };
        assert_eq!(policy.check_spf_alignment(from_domain, &spf_result), false);
    }

    #[test]
    fn test_check_alignement_dkim_strict() {
        let mut policy = Policy::new(ReceiverAction::Reject);
        policy.adkim = Alignement::Strict;

        let from_domain = "a.com";

        let dkim_result = cfdkim::DKIMResult::neutral("notify.a.com".to_owned());
        assert_eq!(
            policy.check_dkim_alignment(from_domain, &dkim_result),
            false
        );

        let dkim_result = cfdkim::DKIMResult::neutral("a.com".to_owned());
        assert_eq!(policy.check_dkim_alignment(from_domain, &dkim_result), true);

        let dkim_result = cfdkim::DKIMResult::neutral("cc.com".to_owned());
        assert_eq!(
            policy.check_dkim_alignment(from_domain, &dkim_result),
            false
        );
    }

    #[test]
    fn test_check_alignement_dkim_relaxed() {
        let mut policy = Policy::new(ReceiverAction::Reject);
        policy.adkim = Alignement::Relaxed;

        let from_domain = "a.com";

        let dkim_result = cfdkim::DKIMResult::neutral("a.com".to_owned());
        assert_eq!(policy.check_dkim_alignment(from_domain, &dkim_result), true);

        let dkim_result = cfdkim::DKIMResult::neutral("notify.a.com".to_owned());
        assert_eq!(policy.check_dkim_alignment(from_domain, &dkim_result), true);

        let dkim_result = cfdkim::DKIMResult::neutral("cc.com".to_owned());
        assert_eq!(
            policy.check_dkim_alignment(from_domain, &dkim_result),
            false
        );
    }
}
