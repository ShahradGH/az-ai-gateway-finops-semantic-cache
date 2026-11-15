# Invoke-ApimAiGatewayPolicySync.ps1
<#
.SYNOPSIS
    Synchronises Azure APIM AI Gateway token-rate limit and semantic caching policies via Invoke-AzRestMethod (Zero Bicep).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$ApimServiceName,

    [Parameter(Mandatory)]
    [string]$ApiId,

    [Parameter()]
    [int]$TokensPerMinute = 50000,

    [Parameter()]
    [ValidateRange(0.70, 0.99)]
    [double]$ScoreThreshold = 0.92,

    [Parameter()]
    [int]$CacheTtlSeconds = 3600,

    [Parameter()]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policyXml = @"
<policies>
  <inbound>
    <base />
    <validate-azure-ad-token tenant-id="contoso.onmicrosoft.com" header-name="Authorization" failed-validation-httpcode="401" output-token-variable-name="entraJwt" />
    <azure-openai-token-limit counter-key="@(context.Variables.GetValueOrDefault&lt;Jwt&gt;(&quot;entraJwt&quot;)?.Claims.GetValueOrDefault(&quot;azp&quot;, &quot;anonymous&quot;))" tokens-per-minute="$TokensPerMinute" estimate-prompt-tokens="true" remaining-tokens-header-name="x-ratelimit-remaining-tokens" />
    <azure-openai-semantic-cache-lookup score-threshold="$ScoreThreshold" embeddings-backend-id="foundry-embeddings-pool" embeddings-backend-auth="system-assigned" ignore-system-messages="true" max-message-count="4">
      <vary-by>@(context.Request.Headers.GetValueOrDefault("x-contoso-tenant-bu", "default"))</vary-by>
    </azure-openai-semantic-cache-lookup>
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
    <azure-openai-semantic-cache-store duration="$CacheTtlSeconds" />
    <llm-emit-token-metric namespace="Contoso.AiGateway.FinOps">
      <dimension name="WorkloadAppId" value="@(context.Variables.GetValueOrDefault&lt;Jwt&gt;(&quot;entraJwt&quot;)?.Claims.GetValueOrDefault(&quot;azp&quot;, &quot;unknown&quot;))" />
      <dimension name="TenantBU" value="@(context.Request.Headers.GetValueOrDefault(&quot;x-contoso-tenant-bu&quot;, &quot;default&quot;))" />
    </llm-emit-token-metric>
  </outbound>
</policies>
"@

$armPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.ApiManagement/service/$ApimServiceName/apis/$ApiId/policies/policy?api-version=2024-05-01"
$body = @{
    properties = @{
        format = 'rawxml'
        value  = $policyXml
    }
} | ConvertTo-Json -Depth 5

if ($DryRun) {
    return [PSCustomObject]@{
        Status          = 'DRY_RUN_PREPARED'
        ArmPath         = $armPath
        TokensPerMinute = $TokensPerMinute
        ScoreThreshold  = $ScoreThreshold
        PolicyXml       = $policyXml
    }
}

$resp = Invoke-AzRestMethod -Method PUT -Path $armPath -Payload $body
if ($resp.StatusCode -ge 400) {
    throw "APIM AI Gateway policy sync failed: HTTP $($resp.StatusCode) - $($resp.Content)"
}

return [PSCustomObject]@{
    Status          = 'SYNCED_TO_APIM'
    ArmPath         = $armPath
    StatusCode      = $resp.StatusCode
    TokensPerMinute = $TokensPerMinute
    ScoreThreshold  = $ScoreThreshold
}
