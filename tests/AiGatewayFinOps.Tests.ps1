BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:CacheEvalScript = Join-Path $script:RepoRoot 'ai/Invoke-SemanticCacheEvaluator.ps1'
    $script:ChargebackScript = Join-Path $script:RepoRoot 'ai/Invoke-TokenChargebackClassifier.ps1'
    $script:CasesPath = Join-Path $script:RepoRoot 'ai/semantic-cache-eval-cases.json'
    $script:ApimSyncScript = Join-Path $script:RepoRoot 'src/Invoke-ApimAiGatewayPolicySync.ps1'
    $script:GraphAlertScript = Join-Path $script:RepoRoot 'graph/Send-FinOpsQuotaAlert.ps1'
    $script:KqlPath = Join-Path $script:RepoRoot 'queries/Apim-SemanticCache-FinOps.kql'
    $script:Cases = Get-Content -Path $script:CasesPath -Raw | ConvertFrom-Json
}

Describe 'AI Gateway FinOps: Token-Rate Governance & Semantic Caching Verification Suite' {
    Context 'AI Subcomponent: Semantic Cache Isolation & Poisoning Boundaries' {
        It 'Serves from Redis on high-similarity clean prompt (CACHE-201)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'CACHE-201' }
            $res = & $script:CacheEvalScript -CacheEvalCase $case
            $res.Decision | Should -Be 'CACHE_HIT_SERVE_FROM_REDIS'
            $res.TokensSaved | Should -Be 600
            $res.EstimatedSavingsUsd | Should -BeGreaterThan 0
        }

        It 'Bypasses semantic cache when PII/secret flag is set (CACHE-202)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'CACHE-202' }
            $res = & $script:CacheEvalScript -CacheEvalCase $case
            $res.Decision | Should -Be 'BYPASS_CACHE_PII_BOUNDARY'
            $res.CacheEligible | Should -BeFalse
        }

        It 'Quarantines cache-poisoning prompt injection (CACHE-203)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'CACHE-203' }
            $res = & $script:CacheEvalScript -CacheEvalCase $case
            $res.Decision | Should -Be 'QUARANTINE_CACHE_POISONING'
            $res.CacheEligible | Should -BeFalse
        }

        It 'Routes low-similarity prompt to Foundry PTU backend (CACHE-204)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'CACHE-204' }
            $res = & $script:CacheEvalScript -CacheEvalCase $case
            $res.Decision | Should -Be 'CACHE_MISS_ROUTE_FOUNDRY_PTU'
            $res.TokensSaved | Should -Be 0
        }

        It 'Denies cross-tenant partition key mismatch' {
            $tampered = [PSCustomObject]@{
                caseId                    = 'CACHE-999'
                tenantBu                  = 'contoso-retail-support'
                promptText                = 'Standard return policy'
                cosineSimilarity          = 0.98
                containsPiiOrSecret       = $false
                cachePartitionKey         = 'contoso-wealth-advisory::advisory-v2'
                estimatedPromptTokens     = 200
                estimatedCompletionTokens = 100
            }
            $res = & $script:CacheEvalScript -CacheEvalCase $tampered
            $res.Decision | Should -Be 'DENY_CROSS_TENANT_PARTITION'
        }
    }

    Context 'Token Chargeback Classifier & APIM REST Policy Sync' {
        It 'Triggers THROTTLE_429_AND_SPILLOVER_PAYGO when net TPM exceeds 100% quota' {
            $window = [PSCustomObject]@{
                BusinessUnit             = 'contoso-retail-support'
                WorkloadAppId            = '11111111-2222-3333-4444-555555555501'
                CostCenterCode           = 'CC-4010'
                ObservedTpm              = 75000
                SemanticCacheTokensSaved = 20000
                AllocatedTpmQuota        = 50000
            }
            $res = & $script:ChargebackScript -TelemetryWindow $window
            $res.NetBackendTpm | Should -Be 55000
            $res.GovernanceAction | Should -Be 'THROTTLE_429_AND_SPILLOVER_PAYGO'
            $res.RequiresTeamsAlert | Should -BeTrue
        }

        It 'Generates valid APIM AI Gateway policy XML in DryRun mode' {
            $sync = & $script:ApimSyncScript -SubscriptionId '00000000-0000-0000-0000-000000000000' -ResourceGroupName 'rg-contoso-aigw' -ApimServiceName 'apim-contoso-gw' -ApiId 'foundry-openai' -DryRun
            $sync.Status | Should -Be 'DRY_RUN_PREPARED'
            $sync.PolicyXml | Should -Match 'azure-openai-token-limit'
            $sync.PolicyXml | Should -Match 'azure-openai-semantic-cache-lookup'
            $sync.PolicyXml | Should -Match 'llm-emit-token-metric'
        }
    }

    Context 'Microsoft Graph v2.x FinOps Alerting & Zero-Leak Governance' {
        It 'Builds valid Teams Adaptive Card payload in DryRun mode' {
            $window = [PSCustomObject]@{
                BusinessUnit             = 'contoso-retail-support'
                WorkloadAppId            = '11111111-2222-3333-4444-555555555501'
                CostCenterCode           = 'CC-4010'
                ObservedTpm              = 75000
                SemanticCacheTokensSaved = 20000
                AllocatedTpmQuota        = 50000
            }
            $verdict = & $script:ChargebackScript -TelemetryWindow $window
            $card = & $script:GraphAlertScript -ChargebackVerdict $verdict -TeamId '00000000-0000-0000-0000-000000000001' -ChannelId '19:finops@thread.tacv2' -DryRun
            $card.Status | Should -Be 'DRY_RUN_PREPARED'
            $card.GraphUri | Should -Match '^https://graph\.microsoft\.com/v1\.0/teams/'
        }

        It 'Contains zero Bicep or Terraform files and zero internal sequence tags' {
            $iac = Get-ChildItem -Path $script:RepoRoot -Recurse -File | Where-Object { $_.Extension -in '.bicep', '.tf' }
            $iac.Count | Should -Be 0
            (Get-Content (Join-Path $script:RepoRoot 'README.md') -Raw) | Should -Not -Match 'Decision Pack 0|mvpfoundry\.alerasoul\.net|idea-019'
            (Get-Content $script:KqlPath -Raw) | Should -Match 'summarize|extend'
            (Get-Item (Join-Path $script:RepoRoot 'docs/AI-GATEWAY-FINOPS-RUNBOOK.md')).Length | Should -BeGreaterThan 2048
        }
    }
}
