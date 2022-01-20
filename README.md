# dmarc

> DMARC ([RFC7489]) implementation

## Features

### Load the policy for a domain

```rust
let policy: Option<dmarc::Policy> = dmarc::load_policy(&logger, &from_domain).await?;
```

The `load_policy` arguments are the following:
- `logger`: [slog]::Logger
- `from_domain`: &str ([RFC5322].From's domain)

### Apply a policy

```rust
let dkim_result: cfdkim::DKIMResult = ...;
let spf_result: SPFResult = ...;

let ctx = dmarc::PolicyContext {
    from_domain: &from_domain,
    logger: &logger,
    dkim_result,
    spf_result,
};

let res: DMARCResult = policy.apply(&ctx);
println!("dmarc={}", res.to_str());
```

`dkim_result` is the result of verifying DKIM using the [cfdkim] crate. In the future it should be a trait.

`spf_result` is the result of verifying SPF.

### Sending feedback report

Not planned yet.

[RFC7489]: https://datatracker.ietf.org/doc/html/rfc7489
[slog]: https://crates.io/crates/slog
[RFC5322]: https://datatracker.ietf.org/doc/html/rfc5322
[cfdkim]: https://crates.io/crates/cfdkim
