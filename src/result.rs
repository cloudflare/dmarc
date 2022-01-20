use crate::policy;

#[derive(PartialEq)]
enum Value {
    Neutral,
    Pass,
    Fail,
}

/// Result of applying a DMARC policy
pub struct DMARCResult {
    value: Value,
    policy: policy::Policy,
}

impl DMARCResult {
    /// Get the result as string (neutral, fail or pass)
    pub fn to_str(&self) -> &'static str {
        match self.value {
            Value::Neutral => "neutral",
            Value::Pass => "pass",
            Value::Fail => "fail",
        }
    }

    /// Constructs a neutral result
    pub(crate) fn neutral(policy: policy::Policy) -> Self {
        Self {
            value: Value::Neutral,
            policy,
        }
    }

    /// Constructs a pass result
    pub(crate) fn pass(policy: policy::Policy) -> Self {
        Self {
            value: Value::Pass,
            policy,
        }
    }

    /// Constructs a fail result
    pub(crate) fn fail(policy: policy::Policy) -> Self {
        Self {
            value: Value::Fail,
            policy,
        }
    }

    /// Checks if the email is supposed to be reject based on the DMARC policy and
    /// its result
    pub fn should_reject(&self) -> bool {
        self.value == Value::Fail && self.policy.action == policy::ReceiverAction::Reject
    }
}
