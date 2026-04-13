# Compliance Evidence Directory

Copy this directory into your project root as `compliance/` and populate the documents below. Preston-Check (P-83 through P-95) verifies the existence and recency of these artifacts. Maintaining them gets you to 100% coverage across all six compliance frameworks.

## Required Documents

### PCI-DSS v4.0 (Requirement 9 + 12)
- `physical-access-policy.md` — Physical security controls, badge system, visitor procedures, data center access
- `information-security-policy.md` — Master information security policy
- `acceptable-use-policy.md` — Employee acceptable use of systems and data
- `risk-assessment.md` — Annual risk assessment with methodology and findings
- `security-awareness-training.md` — Training program description, frequency, topics, completion tracking
- `vendor-management-policy.md` — Third-party risk assessment process and vendor reviews
- `pci-scope-document.md` — Cardholder data environment boundary and data flow diagrams

### SOC 2 Type II
- `capacity-planning.md` — Current capacity, growth projections, scaling strategy
- `sla-commitments.md` — Service level agreements, uptime targets, RTO/RPO definitions
- `data-classification-policy.md` — Classification levels (public, internal, confidential, restricted), handling rules
- `privacy-notice.md` — Customer-facing privacy notice with data collection/use/sharing details

### ISO 27001:2022
- `isms-scope.md` — Information Security Management System scope and boundaries
- `risk-register.md` — Active risk register with risk owners, treatments, and residual risk levels
- `supplier-security-assessment-template.md` — Template for assessing third-party vendor security
- `onboarding-security-checklist.md` — New employee security onboarding procedure
- `offboarding-security-checklist.md` — Employee termination access revocation procedure
- `remote-work-policy.md` — Remote working security requirements
- `cloud-shared-responsibility.md` — AWS/GCP shared responsibility model documentation

### NIST CSF 2.0
- `organizational-context.md` — Business context, stakeholders, legal/regulatory environment
- `risk-management-strategy.md` — Risk appetite, tolerance, prioritization methodology
- `roles-and-responsibilities.md` — Security team structure, CISO, DPO, incident commander roles
- `recovery-communication-plan.md` — Customer/stakeholder notification procedures during incidents

### CIS Controls v8
- `asset-inventory.md` — All deployed services, ports, databases, cloud resources (or reference services.list)
- `vulnerability-management-schedule.md` — Quarterly ASV scans, annual pentests, monthly dependency scans
- `pentest-program.md` — Penetration testing scope, frequency, vendor, remediation tracking

## How It Works

Preston-Check scans for these files (and code references to the concepts they represent) during checks P-83 through P-95. Each check looks for multiple indicators — file names, code patterns, configuration references — so you don't need every single file. But having the full set guarantees 100% coverage.

Files don't need to be in this exact directory. Preston-Check searches up to 5 levels deep from the source_dir. But keeping them in a `compliance/` directory makes them easy to find, update, and audit.

## Maintenance

Review and update these documents quarterly. Many compliance frameworks require annual review cycles. Set a calendar reminder for:
- Monthly: vulnerability scan results, training completion tracking
- Quarterly: risk register review, vendor assessment updates, capacity planning review
- Annually: full policy review, pentest report, risk assessment, training program refresh
