# Azure APIM AI Gateway FinOps & Semantic Caching Runbook

**Operational Scope:** Azure API Management (APIM) AI Gateway policies, Azure Managed Redis semantic vector cache, Provisioned Throughput Unit (PTU) spillover routing, and Microsoft Graph FinOps alerting.
**Owner:** Cloud FinOps & AI Platform Engineering (Contoso Platform)

---

## 1. Control-Plane & Security Invariants

1. **Zero-Declarative-IaC Policy Sync:** All APIM AI Gateway policies (`azure-openai-token-limit`, `azure-openai-semantic-cache-lookup`, `azure-openai-semantic-cache-store`, `llm-emit-token-metric`) are synchronised via `src/Invoke-ApimAiGatewayPolicySync.ps1` using `Invoke-AzRestMethod` against ARM API `2024-05-01`.
2. **Tenant-Isolated Semantic Cache Partitions:** Every cached embedding vector in Azure Managed Redis MUST be prefixed with `<tenantBu>::<domain-version>`. Cross-tenant cache lookups are strictly prohibited (`DENY_CROSS_TENANT_PARTITION`).
3. **PII & Cache-Poisoning Boundaries:** Any prompt containing PII, regulated account identifiers, or prompt-injection override phrases (`QUARANTINE_CACHE_POISONING`) is blocked from entering the shared semantic cache.

---

## 2. L2/L3 Incident Triage Procedures

### Scenario A: Elevated `429 Too Many Requests` on PTU Backend
- **Symptom:** `queries/Apim-SemanticCache-FinOps.kql` reports `Throttled429 > 0` for a specific `WorkloadAppId`.
- **Diagnosis:**
  1. Run `ai/Invoke-TokenChargebackClassifier.ps1` against the 15-minute telemetry window to determine whether `BurnRatio >= 1.0`.
  2. Check `CacheHitRatioPct` in Log Analytics; a sudden drop below 25% indicates either a new prompt template or an overly strict `score-threshold` (> 0.95).
- **Remediation:**
  1. If the spike is legitimate business traffic, approve temporary PAYGO spillover via the Microsoft Teams Adaptive Card (`graph/Send-FinOpsQuotaAlert.ps1`).
  2. If the spike is caused by a runaway loop in a single microservice, enforce a tighter `tokens-per-minute` cap using `Invoke-ApimAiGatewayPolicySync.ps1`.

### Scenario B: Suspected Semantic Cache Poisoning (`QUARANTINE_CACHE_POISONING`)
- **Symptom:** `ai/Invoke-SemanticCacheEvaluator.ps1` flags a prompt attempting to override system instructions or force cross-tenant caching.
- **Remediation:**
  1. Flush the affected `<tenantBu>::*` keyspace in Azure Managed Redis.
  2. Audit the calling `WorkloadAppId` in Entra ID sign-in logs and rotate its federated credential if compromised.

### Scenario C: Stale or Low-Quality Cached Responses
- **Symptom:** End users report outdated answers after a knowledge-base update.
- **Remediation:** Increment the partition suffix (`kb-v4` -> `kb-v5`) in the APIM `vary-by` header expression and sync via `Invoke-ApimAiGatewayPolicySync.ps1`.
