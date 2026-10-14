# entra-ca-diff 🛡️

An identity-aware semantic comparison engine designed to prevent catastrophic security regressions, accidental MFA bypasses, and configuration drift in **Microsoft Entra ID Conditional Access policies**.

Built as a high-visibility DevSecOps guardrail that integrates directly into **GitOps deployment pipelines** or runs locally via a **Command Line Interface (CLI)**.

---

## 🚀 The Core Problem

When managing Entra ID infrastructure-as-code (using tools like `EntraExporter` or Terraform), changes to Conditional Access policies are reviewed as raw JSON text streams. Standard line-by-line `git diff` operations fail to capture semantic context:
* A standard text diff highlights modified string properties or shifted arrays.
* A single misplaced string (like adding `"All"` to an `excludeUsers` block) can silently disable global security rules, leaving the entire tenant vulnerable to takeover.

`entra-ca-diff` resolves this exposure by enforcing a strict **Data Control Contract** against the native Microsoft Graph schema before modifications can be merged or deployed to production.

---

## 🛠️ System Architecture

The project is structured as a decoupled, testable Python package:

```text
entra-ca-diff/
├── requirements.txt         # Package definitions (Pydantic v2.14+)
├── README.md                # Engineering documentation
├── src/
│   ├── models.py            # Microsoft Graph schema abstraction layer
│   └── engine.py            # Semantic evaluation logic and guardrails
└── tests/
    ├── test_samples/        # Dev vs. Production mock JSON policies
    └── test_engine.py       # Validation suites
```

---

## 🔒 Security Guardrails Checked

Instead of basic text matches, the core semantic evaluation engine validates incoming configurations against three primary, high-stakes security exposures:

1. **Enforcement State Downshifting:** Triggers an alert if a policy transitions from `enabled` to `disabled` or shifts into `enabledForReportingButNotEnforced` (Report-Only) mode.
2. **MFA Control Retractions:** Catches instances where robust authentication requirement controls (like multi-factor authentication or custom authentication strengths) are stripped from the policy configuration.
3. **Universal Exclusions Leaks:** Intercepts critical validation faults where broad exclusion identifiers (such as the `"All"` users bypass string) leak into the policy footprint, accidentally exempting the entire enterprise.

---

## 🧑‍💻 Technical Stack & Compliance

* **Runtime Environment:** Python 3.14+ (leveraging native optimization paths)
* **Data Integration Layer:** Pydantic v2.14+ (strict, type-safe API object mapping with automatic camelCase transformation support)
* **Target Delivery Channels:** 
  * Local administrative utility execution script
  * Automated GitHub Actions pipeline workflow component targeting automated Pull Request reviews
