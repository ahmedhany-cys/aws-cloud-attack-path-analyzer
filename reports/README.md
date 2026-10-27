# Reports

`reports/sample/` contains reports generated from `fixtures/sample_environment.json`, a
**synthetic** environment. Nothing in them describes a real AWS account: the account ids,
identities, buckets and functions are fictional, and the findings exist to demonstrate the
analyzer. Each report carries that notice in its header.

Regenerate them with:

```bash
make reports
```

Everything else written under `reports/` (for example the output of your own analyses or of
`attackpath aws-scan --analyze`) is ignored by Git so that real account data is never committed by
accident. Keep it that way.
