quick_error! {
    #[derive(Debug, PartialEq)]
    /// DMARC errors
    pub enum DMARCError {
        PolicyParseError(err: String) {
            display("failed to parse policy: {}", err)
        }
        MissingRequiredTag(tag: &'static str) {
            display("missing required tag: {}", tag)
        }
        IncompatibleVersion(value: String) {
            display("incompatible version: {}", value)
        }
        UnknownInternalError(err: String) {
            display("internal error: {}", err)
        }
    }
}
