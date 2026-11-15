# Invoke-TokenChargebackClassifier.ps1
<#
.SYNOPSIS
    Classifies Azure APIM AI Gateway token consumption by Entra Workload ID and computes FinOps quota governance actions.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$TelemetryWindow,

    [Parameter()]
    [ValidateRange(0.50, 1.00)]
    [double]$BurnRateAlertThreshold = 0.85
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$allocatedTpm = [double]$TelemetryWindow.AllocatedTpmQuota
if ($allocatedTpm -le 0) {
    throw "AllocatedTpmQuota must be greater than zero for WorkloadAppId $($TelemetryWindow.WorkloadAppId)."
}

$observedTpm = [double]$TelemetryWindow.ObservedTpm
$cacheHitTokens = [double]$TelemetryWindow.SemanticCacheTokensSaved
$netBackendTpm = [math]::Max(0.0, $observedTpm - $cacheHitTokens)
$burnRatio = [math]::Round($netBackendTpm / $allocatedTpm, 4)

$action = if ($burnRatio -ge 1.0) {
    'THROTTLE_429_AND_SPILLOVER_PAYGO'
}
elseif ($burnRatio -ge $BurnRateAlertThreshold) {
    'ALERT_FINOPS_QUOTA_APPROACHING'
}
else {
    'PERMIT_WITHIN_PTU_ENVELOPE'
}

return [PSCustomObject]@{
    BusinessUnit      = $TelemetryWindow.BusinessUnit
    WorkloadAppId     = $TelemetryWindow.WorkloadAppId
    CostCenterCode    = $TelemetryWindow.CostCenterCode
    ObservedTpm       = $observedTpm
    CacheSavedTpm     = $cacheHitTokens
    NetBackendTpm     = $netBackendTpm
    AllocatedTpmQuota = $allocatedTpm
    BurnRatio         = $burnRatio
    GovernanceAction  = $action
    RequiresTeamsAlert = ($action -ne 'PERMIT_WITHIN_PTU_ENVELOPE')
}
