# Invoke-SemanticCacheEvaluator.ps1
<#
.SYNOPSIS
    Evaluates semantic cache eligibility, tenant partition isolation, and cache-poisoning boundaries for Azure APIM AI Gateway.
.DESCRIPTION
    Enforces strict epistemic and security gates before serving or storing embeddings in Azure Managed Redis:
    1. Rejects prompt-injection / cross-tenant cache-poisoning attempts.
    2. Bypasses cache whenever PII/confidentiality flags are present.
    3. Verifies tenant-scoped partition key prefixing and cosine similarity >= threshold.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$CacheEvalCase,

    [Parameter()]
    [ValidateRange(0.70, 0.99)]
    [double]$DefaultSimilarityThreshold = 0.92,

    [Parameter()]
    [double]$BlendedCostPer1kTokensUsd = 0.0075
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PromptCachePoisoning {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$PromptText)

    $poisonPatterns = @(
        '(?i)ignore\s+(all\s+)?previous\s+(system\s+)?prompt',
        '(?i)cache\s+this\s+response\s+for\s+all\s+tenants',
        '(?i)bypass\s+partition\s+key',
        '(?i)exfiltrate\s+system\s+instructions'
    )
    foreach ($pattern in $poisonPatterns) {
        if ($PromptText -match $pattern) { return $true }
    }
    return $false
}

# 1. Cache-Poisoning & Prompt-Injection Boundary
if (Test-PromptCachePoisoning -PromptText $CacheEvalCase.promptText) {
    return [PSCustomObject]@{
        CaseId             = $CacheEvalCase.caseId
        TenantBu           = $CacheEvalCase.tenantBu
        Decision           = 'QUARANTINE_CACHE_POISONING'
        CacheEligible      = $false
        TokensSaved        = 0
        EstimatedSavingsUsd = 0.0
        Reason             = 'Prompt matched cache-poisoning signature; blocked from Redis semantic store.'
    }
}

# 2. Tenant Partition Isolation Check
$expectedPrefix = "$($CacheEvalCase.tenantBu)::"
if (-not $CacheEvalCase.cachePartitionKey.StartsWith($expectedPrefix)) {
    return [PSCustomObject]@{
        CaseId             = $CacheEvalCase.caseId
        TenantBu           = $CacheEvalCase.tenantBu
        Decision           = 'DENY_CROSS_TENANT_PARTITION'
        CacheEligible      = $false
        TokensSaved        = 0
        EstimatedSavingsUsd = 0.0
        Reason             = "Partition key '$($CacheEvalCase.cachePartitionKey)' violates tenant isolation prefix '$expectedPrefix'."
    }
}

# 3. PII / Confidentiality Boundary (Never cache regulated prompts in shared vector index)
if ($CacheEvalCase.containsPiiOrSecret) {
    return [PSCustomObject]@{
        CaseId             = $CacheEvalCase.caseId
        TenantBu           = $CacheEvalCase.tenantBu
        Decision           = 'BYPASS_CACHE_PII_BOUNDARY'
        CacheEligible      = $false
        TokensSaved        = 0
        EstimatedSavingsUsd = 0.0
        Reason             = 'Prompt flagged with PII/secret sensitivity; bypassing semantic cache to prevent cross-session leakage.'
    }
}

$threshold = if ($CacheEvalCase.PSObject.Properties['similarityThreshold']) {
    [double]$CacheEvalCase.similarityThreshold
} else {
    $DefaultSimilarityThreshold
}

$totalTokens = [int]$CacheEvalCase.estimatedPromptTokens + [int]$CacheEvalCase.estimatedCompletionTokens

# 4. Cosine Similarity Gate
if ([double]$CacheEvalCase.cosineSimilarity -ge $threshold) {
    $savings = [math]::Round(($totalTokens / 1000.0) * $BlendedCostPer1kTokensUsd, 6)
    return [PSCustomObject]@{
        CaseId              = $CacheEvalCase.caseId
        TenantBu            = $CacheEvalCase.tenantBu
        Decision            = 'CACHE_HIT_SERVE_FROM_REDIS'
        CacheEligible       = $true
        TokensSaved         = $totalTokens
        EstimatedSavingsUsd = $savings
        Reason              = "Cosine similarity $($CacheEvalCase.cosineSimilarity) >= threshold $threshold inside isolated partition."
    }
}

return [PSCustomObject]@{
    CaseId              = $CacheEvalCase.caseId
    TenantBu            = $CacheEvalCase.tenantBu
    Decision            = 'CACHE_MISS_ROUTE_FOUNDRY_PTU'
    CacheEligible       = $true
    TokensSaved         = 0
    EstimatedSavingsUsd = 0.0
    Reason              = "Cosine similarity $($CacheEvalCase.cosineSimilarity) < threshold $threshold; routing to Foundry PTU backend."
}
