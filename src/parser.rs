use crate::policy::{Alignement, ReceiverAction};
use crate::DMARCError;

pub use cfdkim::Tag;

pub(crate) fn parse(input: &str) -> Result<Vec<Tag>, DMARCError> {
    // DMARC records follow the extensible "tag-value" syntax for DNS-based key
    // records defined in DKIM.
    let (_, tags) = cfdkim::parse_tag_list(input)
        .map_err(|err| DMARCError::PolicyParseError(err.to_string()))?;

    Ok(tags)
}

pub(crate) fn parse_alignement_mode(input: &str) -> Alignement {
    match input {
        "r" => Alignement::Relaxed,
        "s" => Alignement::Strict,
        _ => Alignement::default(),
    }
}

pub(crate) fn parse_receiver_action(input: &str) -> Result<ReceiverAction, DMARCError> {
    match input {
        "none" => Ok(ReceiverAction::None),
        "quarantine" => Ok(ReceiverAction::Quarantine),
        "reject" => Ok(ReceiverAction::Reject),
        v => Err(DMARCError::PolicyParseError(format!(
            "invalid receiver policy (p): {}",
            v
        ))),
    }
}

pub(crate) fn parse_percentage(input: &str) -> usize {
    let default = 100;

    if let Ok(value) = input.parse::<usize>() {
        if value > 100 {
            default
        } else {
            value
        }
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse("v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com").unwrap(),
            vec![
                Tag {
                    name: "v".to_string(),
                    value: "DMARC1".to_string(),
                    raw_value: "DMARC1".to_string()
                },
                Tag {
                    name: "p".to_string(),
                    value: "none".to_string(),
                    raw_value: "none".to_string()
                },
                Tag {
                    name: "rua".to_string(),
                    value: "mailto:dmarc@yourdomain.com".to_string(),
                    raw_value: "mailto:dmarc@yourdomain.com".to_string()
                }
            ]
        );
    }
}
