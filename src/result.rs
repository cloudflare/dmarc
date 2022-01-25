use crate::policy;

#[derive(PartialEq)]
enum Value {
    None,
    Neutral,
    Pass,
    Fail,
}

/// Result of applying a DMARC policy
pub struct DMARCResult {
    value: Value,
    policy: Option<policy::Policy>,
}

impl DMARCResult {
    /// Get the result as string (neutral, fail or pass)
    pub fn to_str(&self) -> &'static str {
        match self.value {
            Value::None => "none",
            Value::Neutral => "neutral",
            Value::Pass => "pass",
            Value::Fail => "fail",
        }
    }

    /// Constructs a neutral result
    pub fn neutral(policy: policy::Policy) -> Self {
        Self {
            value: Value::Neutral,
            policy: Some(policy),
        }
    }

    /// Constructs a pass result
    pub fn pass(policy: policy::Policy) -> Self {
        Self {
            value: Value::Pass,
            policy: Some(policy),
        }
    }

    /// Constructs a fail result
    pub fn fail(policy: policy::Policy) -> Self {
        Self {
            value: Value::Fail,
            policy: Some(policy),
        }
    }

    /// Constructs a none result
    pub fn none() -> Self {
        Self {
            value: Value::None,
            policy: None,
        }
    }

    /// Checks if the email is supposed to be reject based on the DMARC policy and
    /// its result
    pub fn should_reject(&self) -> bool {
        if let Some(policy) = &self.policy {
            self.value == Value::Fail && policy.action == policy::ReceiverAction::Reject
        } else {
            false
        }
    }
}
