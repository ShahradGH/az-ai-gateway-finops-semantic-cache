# Send-FinOpsQuotaAlert.ps1
<#
.SYNOPSIS
    Dispatches an AI Gateway FinOps Token Quota & PTU Spillover Adaptive Card to Microsoft Teams via Graph v2.x.
.DESCRIPTION
    Resolves Entra Workload ID attribution and posts a structured Adaptive Card v1.5 to the FinOps
    governance channel via Invoke-MgGraphRequest when TPM burn rate breaches alert or throttle thresholds.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$ChargebackVerdict,

    [Parameter(Mandatory)]
    [string]$TeamId,

    [Parameter(Mandatory)]
    [string]$ChannelId,

    [Parameter()]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cardColour = if ($ChargebackVerdict.GovernanceAction -eq 'THROTTLE_429_AND_SPILLOVER_PAYGO') { 'Attention' } else { 'Warning' }

$adaptiveCard = [ordered]@{
    type    = 'AdaptiveCard'
    version = '1.5'
    body    = @(
        @{
            type   = 'TextBlock'
            text   = "AI Gateway FinOps Alert: $($ChargebackVerdict.BusinessUnit)"
            weight = 'Bolder'
            size   = 'Medium'
            color  = $cardColour
        }
        @{
            type  = 'FactSet'
            facts = @(
                @{ title = 'Entra Workload ID'; value = $ChargebackVerdict.WorkloadAppId }
                @{ title = 'Cost Centre'; value = $ChargebackVerdict.CostCenterCode }
                @{ title = 'Observed TPM'; value = "$($ChargebackVerdict.ObservedTpm)" }
                @{ title = 'Cache Saved TPM'; value = "$($ChargebackVerdict.CacheSavedTpm)" }
                @{ title = 'Net Backend TPM'; value = "$($ChargebackVerdict.NetBackendTpm)" }
                @{ title = 'PTU Burn Ratio'; value = "$($ChargebackVerdict.BurnRatio)" }
                @{ title = 'Governance Action'; value = $ChargebackVerdict.GovernanceAction }
            )
        }
    )
    actions = @(
        @{
            type  = 'Action.Submit'
            title = 'Approve Temporary PAYGO Spillover'
            data  = @{ action = 'approve_paygo_spillover'; workloadAppId = $ChargebackVerdict.WorkloadAppId }
        }
        @{
            type  = 'Action.Submit'
            title = 'Enforce Hard 429 Cap'
            data  = @{ action = 'enforce_429_cap'; workloadAppId = $ChargebackVerdict.WorkloadAppId }
        }
    )
}

$attachmentId = [guid]::NewGuid().ToString()
$graphPayload = [ordered]@{
    body = @{
        contentType = 'html'
        content     = "<attachment id=`"$attachmentId`"></attachment>"
    }
    attachments = @(
        @{
            id          = $attachmentId
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = ($adaptiveCard | ConvertTo-Json -Depth 12 -Compress)
        }
    )
}

$graphUri = "https://graph.microsoft.com/v1.0/teams/$TeamId/channels/$ChannelId/messages"

if ($DryRun) {
    return [PSCustomObject]@{
        Status       = 'DRY_RUN_PREPARED'
        GraphUri     = $graphUri
        AttachmentId = $attachmentId
        Payload      = $graphPayload
    }
}

$resp = Invoke-MgGraphRequest -Method POST -Uri $graphUri -Body ($graphPayload | ConvertTo-Json -Depth 12) -ContentType 'application/json'
return [PSCustomObject]@{
    Status       = 'DISPATCHED_TO_TEAMS'
    GraphUri     = $graphUri
    MessageId    = $resp.id
    AttachmentId = $attachmentId
}
