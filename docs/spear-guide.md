# Spear Guide

Spear performs only explicitly authorized assessment work. It never accepts a boolean acknowledgement. `run` and `recon` require a signed JSON scope manifest, validate its time window and target membership, reject private/reserved addresses, and write an audit log before the legacy engine starts.

Create an unsigned `scope.json`:

```json
{
  "version": 1,
  "targets": ["https://assessment.example.com/api"],
  "valid_from": "2026-07-25T09:00:00+08:00",
  "valid_until": "2026-07-25T18:00:00+08:00",
  "prohibited_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
  "signer": "security-team",
  "signature_algorithm": "hmac-sha256"
}
```

Sign it with the organization-held secret, then run a scoped command:

```powershell
$env:DEEPSEC_SCOPE_SIGNING_KEY = "store-this-in-your-secret-manager"
deepsec scope sign .\scope.json
deepsec spear run https://assessment.example.com/api --authorized .\scope.json --mode standard
deepsec spear recon https://assessment.example.com/api --authorized .\scope.json
```

The signer must provide the same secret to the operator through an approved channel. Altering a signed field invalidates the manifest. Direct targets in `10/8`, `172.16/12`, `192.168/16`, `127/8`, loopback, link-local, multicast, reserved, and unspecified ranges are rejected even if listed in the manifest. Review `~/.deepsec/runs/<id>/audit.log` after every run.
