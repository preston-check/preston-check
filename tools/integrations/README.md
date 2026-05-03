# Compliance Platform Integrations

Push Preston-Check audit reports directly into the major compliance platforms as evidence-of-control. Each integration is a small shell script that reads a Preston-Check report and posts to the platform's public API.

## Why these matter

Compliance platform integrations are the highest-leverage moat we can build outside the SaaS dashboard itself. Each platform has tens of thousands of fintech customers going through SOC 2 / ISO 27001 / HIPAA / PCI-DSS audit prep. Customers of those platforms become customers of Preston-Check the moment we appear as a trusted evidence source. The technical work is small; the GTM payoff is enormous.

The pattern that works:

1. Build the integration adapter (this directory)
2. Submit it to the platform's integration marketplace
3. Get listed as a recommended evidence source
4. Co-marketing announcement
5. Inbound customer requests start arriving

Drata, Vanta, and Secureframe each operate ~5,000-15,000 active fintech customers. A single integration listing is worth more than a year of direct sales.

## Available integrations

| Platform | Script | API docs |
|---|---|---|
| Drata | `drata/push-evidence.sh` | <https://developers.drata.com/> |
| Vanta | `vanta/push-evidence.sh` | <https://developer.vanta.com/> |
| Secureframe | `secureframe/push-evidence.sh` | <https://docs.secureframe.com/api> |

## Usage

Each script reads a Preston-Check report (`.md` file from `--report`) and pushes evidence to the platform. Set the platform's API key as an env var, then run:

```bash
# After running a Preston-Check scan that produces report.md:
preston-check --framework "PCI-DSS" --report pci-audit.md

# Push to Drata
DRATA_API_KEY=xxx DRATA_WORKSPACE_ID=yyy \
  tools/integrations/drata/push-evidence.sh pci-audit.md

# Push to Vanta
VANTA_API_TOKEN=xxx \
  tools/integrations/vanta/push-evidence.sh pci-audit.md

# Push to Secureframe
SECUREFRAME_API_KEY=xxx \
  tools/integrations/secureframe/push-evidence.sh pci-audit.md
```

## CI integration

Add to your existing GitHub Actions workflow after the Preston-Check step:

```yaml
- name: Push to Drata
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  env:
    DRATA_API_KEY: ${{ secrets.DRATA_API_KEY }}
    DRATA_WORKSPACE_ID: ${{ secrets.DRATA_WORKSPACE_ID }}
  run: ./tools/integrations/drata/push-evidence.sh preston-check-report.md
```

## Adding a new platform

Each integration is a single shell script that:

1. Reads the report file path as `$1`
2. Validates required env vars
3. Extracts summary metrics from the markdown
4. POSTs to the platform's API
5. Outputs OK/FAILED for each control

Use `drata/push-evidence.sh` as the template. New integrations welcome via PR.

Planned next:

- **Tugboat Logic** — common with mid-market US fintechs
- **OneTrust GRC** — enterprise-tier compliance platforms
- **Hyperproof** — emerging player with auditor relationships
- **AuditBoard** — Big 4 partner integration
