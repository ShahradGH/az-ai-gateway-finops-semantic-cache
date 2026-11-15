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
    [double]$BlendedCostPer1kTokensUsd = 0.0075,

    [Parameter()]
    [string]$FoundryEndpoint = '',

    [Parameter()]
    [string]$FoundryApiKey = '',

    [Parameter()]
    [string]$FoundryDeployment = 'gpt-4o',

    [Parameter()]
    [string]$FoundryApiVersion = '2024-10-21',

    [Parameter()]
    [switch]$UseLiveFoundry
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($UseLiveFoundry) {
    if ([string]::IsNullOrWhiteSpace($FoundryEndpoint)) {
        throw [System.ArgumentException]::new('Fail-closed: -FoundryEndpoint is required when -UseLiveFoundry is specified.')
    }
    if ($FoundryEndpoint -notmatch '^https://') {
        throw [System.ArgumentException]::new('Fail-closed: -FoundryEndpoint must use https://.')
    }
}

function Get-FoundryAuthHeader {
    param([string]$ApiKey)
    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
        return @{
            'api-key'      = $ApiKey
            'Content-Type' = 'application/json'
        }
    }
    if (Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue) {
        $tok = Get-AzAccessToken -ResourceUrl 'https://cognitiveservices.azure.com' -ErrorAction Stop
        $rawToken = if ($tok.Token -is [System.Security.SecureString]) {
            [System.Net.NetworkCredential]::new('', $tok.Token).Password
        } else {
            [string]$tok.Token
        }
        return @{
            'Authorization' = "Bearer $rawToken"
            'Content-Type'  = 'application/json'
        }
    }
    $imdsUri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://cognitiveservices.azure.com'
    $imdsResp = Invoke-RestMethod -Method Get -Uri $imdsUri -Headers @{ Metadata = 'true' } -TimeoutSec 5 -ErrorAction Stop
    return @{
        'Authorization' = "Bearer $($imdsResp.access_token)"
        'Content-Type'  = 'application/json'
    }
}

function Invoke-FoundryJsonInference {
    param(
        [string]$Endpoint,
        [string]$ApiKey,
        [string]$Deployment,
        [string]$ApiVersion,
        [string]$SystemPrompt,
        [hashtable]$Payload
    )
    $uri = if ($Endpoint -match '/chat/completions') {
        $Endpoint
    } else {
        "$($Endpoint.TrimEnd('/'))/openai/deployments/$Deployment/chat/completions?api-version=$ApiVersion"
    }
    $headers = Get-FoundryAuthHeader -ApiKey $ApiKey
    $body = @{
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
        messages        = @(
            @{ role = 'system'; content = $SystemPrompt },
            @{ role = 'user'; content = ($Payload | ConvertTo-Json -Depth 6 -Compress) }
        )
    } | ConvertTo-Json -Depth 8 -Compress

    $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -TimeoutSec 30 -ErrorAction Stop
    $content = $resp.choices[0].message.content
    return ($content | ConvertFrom-Json -ErrorAction Stop)
}

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
$inferenceMode = 'DETERMINISTIC_LOCAL'
$foundryRationale = $null

$deterministicDecision = if ([double]$CacheEvalCase.cosineSimilarity -ge $threshold) {
    'CACHE_HIT_SERVE_FROM_REDIS'
} else {
    'CACHE_MISS_ROUTE_FOUNDRY_PTU'
}

if ($UseLiveFoundry) {
    $allowedDecisions = @('CACHE_HIT_SERVE_FROM_REDIS', 'CACHE_MISS_ROUTE_FOUNDRY_PTU', 'QUARANTINE_CACHE_POISONING', 'BYPASS_CACHE_PII_BOUNDARY')
    try {
        $foundryResult = Invoke-FoundryJsonInference `
            -Endpoint $FoundryEndpoint `
            -ApiKey $FoundryApiKey `
            -Deployment $FoundryDeployment `
            -ApiVersion $FoundryApiVersion `
            -SystemPrompt 'You are an Azure APIM AI Gateway semantic cache evaluator. Return JSON with keys: decision (CACHE_HIT_SERVE_FROM_REDIS|CACHE_MISS_ROUTE_FOUNDRY_PTU|QUARANTINE_CACHE_POISONING|BYPASS_CACHE_PII_BOUNDARY), rationale (string).' `
            -Payload @{
                caseId               = $CacheEvalCase.caseId
                tenantBu             = $CacheEvalCase.tenantBu
                cosineSimilarity     = [double]$CacheEvalCase.cosineSimilarity
                similarityThreshold  = $threshold
                containsPiiOrSecret  = [bool]$CacheEvalCase.containsPiiOrSecret
                deterministicVerdict = $deterministicDecision
            }

        $llmDecision = if ($null -ne $foundryResult.PSObject.Properties['decision']) { [string]$foundryResult.decision } else { '' }
        if ($llmDecision -in $allowedDecisions) {
            $deterministicDecision = $llmDecision
            $inferenceMode = 'LIVE_FOUNDRY'
            if ($null -ne $foundryResult.PSObject.Properties['rationale']) {
                $foundryRationale = [string]$foundryResult.rationale
            }
        } else {
            Write-Warning "Foundry returned invalid cache decision '$llmDecision'; falling back to deterministic gate."
            $inferenceMode = 'DETERMINISTIC_FALLBACK'
        }
    } catch {
        Write-Warning "Live Foundry inference failed ($($_.Exception.Message)); falling back to deterministic gate."
        $inferenceMode = 'DETERMINISTIC_FALLBACK'
    }
}

# 4. Cosine Similarity Gate (or validated Foundry decision)
if ($deterministicDecision -eq 'CACHE_HIT_SERVE_FROM_REDIS') {
    $savings = [math]::Round(($totalTokens / 1000.0) * $BlendedCostPer1kTokensUsd, 6)
    return [PSCustomObject]@{
        CaseId              = $CacheEvalCase.caseId
        TenantBu            = $CacheEvalCase.tenantBu
        Decision            = 'CACHE_HIT_SERVE_FROM_REDIS'
        CacheEligible       = $true
        TokensSaved         = $totalTokens
        EstimatedSavingsUsd = $savings
        Reason              = "Cosine similarity $($CacheEvalCase.cosineSimilarity) >= threshold $threshold inside isolated partition."
        InferenceMode       = $inferenceMode
        FoundryRationale    = $foundryRationale
    }
}

$isEligible = ($deterministicDecision -eq 'CACHE_MISS_ROUTE_FOUNDRY_PTU')
return [PSCustomObject]@{
    CaseId              = $CacheEvalCase.caseId
    TenantBu            = $CacheEvalCase.tenantBu
    Decision            = $deterministicDecision
    CacheEligible       = $isEligible
    TokensSaved         = 0
    EstimatedSavingsUsd = 0.0
    Reason              = if ($foundryRationale) { $foundryRationale } else { "Cosine similarity $($CacheEvalCase.cosineSimilarity) < threshold $threshold; routing to Foundry PTU backend." }
    InferenceMode       = $inferenceMode
    FoundryRationale    = $foundryRationale
}
