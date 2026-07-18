# devsecops — sample OPA policies

Sample [Open Policy Agent](https://www.openpolicyagent.org/) (Rego) policies for a
DevSecOps guardrails demo, covering five platforms:

| Platform     | Package             | Evaluated against |
|--------------|----------------------|--------------------|
| `aws/`       | `aws.security`       | `terraform show -json` plan (aws provider resources) |
| `azure/`     | `azure.security`     | `terraform show -json` plan (azurerm provider resources) |
| `gcp/`       | `gcp.security`       | `terraform show -json` plan (google provider resources) |
| `kubernetes/`| `kubernetes.security`| Pod manifest or Gatekeeper/conftest `AdmissionReview` |
| `databricks/`| `databricks.security`| `terraform show -json` plan (databricks provider resources) |

Each platform directory contains:

- `policy.rego` — the deny rules
- `policy_test.rego` — unit tests (`opa test`)
- `examples/violating.json` and `examples/compliant.json` — sample inputs for manual `opa eval`

These are **illustrative samples** for a demo/training environment — trim the resource
attributes to what your real Terraform plans or admission requests actually contain,
and extend the allow-lists (node types, tags, ports) to match your organization's
standards before using them as real guardrails.

## Run all tests

```bash
opa test devsecops/ -v
```

## Evaluate a single policy against an example input

```bash
opa eval -d devsecops/aws/policy.rego -i devsecops/aws/examples/violating.json 'data.aws.security.deny'
opa eval -d devsecops/aws/policy.rego -i devsecops/aws/examples/compliant.json 'data.aws.security.deny'
```

Swap `aws` for `azure`, `gcp`, `kubernetes`, or `databricks` to try the other platforms.

## Using with Conftest

These policies also work unmodified with [Conftest](https://www.conftest.dev/), which is
convenient for CI:

```bash
conftest test --policy devsecops/kubernetes deployment.yaml
```

## Wiring into CI / gatekeeping

- **Terraform (aws/azure/gcp/databricks):** run `terraform show -json plan.tfplan > plan.json`,
  then `opa eval` or `conftest test` against `plan.json` before `terraform apply`.
- **Kubernetes:** deploy as an OPA Gatekeeper `ConstraintTemplate`, or run `conftest test`
  against manifests in CI prior to `kubectl apply`.
