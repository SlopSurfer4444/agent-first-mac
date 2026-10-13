$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$ProfileName = "codex-windows-host-ssh-remote-control-isolation"
$FlagName = "CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED"
$SkipFlagName = "CODEX_SSH_SKIP_APP_SERVER_BOOT"
$Directive = "SetEnv $FlagName=1"
$SkipDirective = "SetEnv $SkipFlagName=true"
$CombinedDirective = "SetEnv $FlagName=1 $SkipFlagName=true"
$BeginMarker = "# BEGIN AIDev $ProfileName"
$EndMarker = "# END AIDev $ProfileName"
$ConfigPath = Join-Path $env:ProgramData "ssh\sshd_config"
$SshdPath = Join-Path $env:WINDIR "System32\OpenSSH\sshd.exe"
$StateDirectory = Join-Path $env:ProgramData "AIDev\state\$ProfileName"
$ReceiptPath = Join-Path $StateDirectory "receipt.json"
$CommitPattern = "^[0-9a-f]{40}$"

function Emit-Result([hashtable] $Payload, [int] $ExitCode = 0) {
    $Payload["profile"] = $ProfileName
    $Payload | ConvertTo-Json -Compress -Depth 6
    exit $ExitCode
}

function Block([string] $Reason) {
    Emit-Result @{ verdict = "BLOCKED"; reason = $Reason } 1
}

function Get-Sha256([byte[]] $Bytes) {
    $Hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Hasher.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
}

function Get-StrictUtf8([byte[]] $Bytes) {
    $Encoding = New-Object System.Text.UTF8Encoding($false, $true)
    return $Encoding.GetString($Bytes)
}

function Get-Newline([string] $Text) {
    if ($Text.Contains("`r`n")) {
        if ($Text.Replace("`r`n", "").Contains("`n")) { Block "mixed_line_endings" }
        return "`r`n"
    }
    return "`n"
}

function Get-ManagedBlock([string] $Newline) {
    return $BeginMarker + $Newline + $CombinedDirective + $Newline + $EndMarker + $Newline
}

function Get-SplitManagedBlock([string] $Newline) {
    return $BeginMarker + $Newline + $Directive + $Newline + $SkipDirective + $Newline + $EndMarker + $Newline
}

function Get-LegacyManagedBlock([string] $Newline) {
    return $BeginMarker + $Newline + $Directive + $Newline + $EndMarker + $Newline
}

function Get-Receipt {
    if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) { return $null }
    try {
        $Receipt = Get-Content -LiteralPath $ReceiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Block "invalid_receipt"
    }
    if ($Receipt.schema -notin @(1, 2) -or $Receipt.profile -ne $ProfileName -or
        $Receipt.commit -notmatch $CommitPattern -or
        $Receipt.beforeHash -notmatch "^[0-9a-f]{64}$" -or
        $Receipt.afterHash -notmatch "^[0-9a-f]{64}$") {
        Block "invalid_receipt"
    }
    if ($Receipt.schema -eq 2) {
        if ($Receipt.previousMode -ne "legacy_isolation" -or
            $Receipt.previousCommit -notmatch $CommitPattern -or
            $Receipt.previousAfterHash -notmatch "^[0-9a-f]{64}$") {
            Block "invalid_receipt"
        }
    }
    return $Receipt
}

function Get-ConfigState {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { Block "sshd_config_missing" }
    if (-not (Test-Path -LiteralPath $SshdPath -PathType Leaf)) { Block "sshd_binary_missing" }
    $Item = Get-Item -LiteralPath $ConfigPath -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Block "sshd_config_reparse_point" }
    $Bytes = [IO.File]::ReadAllBytes($ConfigPath)
    try { $Text = Get-StrictUtf8 $Bytes } catch { Block "sshd_config_not_utf8" }
    $Newline = Get-Newline $Text
    $Block = Get-ManagedBlock $Newline
    $SplitBlock = Get-SplitManagedBlock $Newline
    $LegacyBlock = Get-LegacyManagedBlock $Newline
    $BeginCount = ([regex]::Matches($Text, [regex]::Escape($BeginMarker))).Count
    $EndCount = ([regex]::Matches($Text, [regex]::Escape($EndMarker))).Count
    $ExactCount = ([regex]::Matches($Text, [regex]::Escape($Block))).Count
    $SplitExactCount = ([regex]::Matches($Text, [regex]::Escape($SplitBlock))).Count
    $LegacyExactCount = ([regex]::Matches($Text, [regex]::Escape($LegacyBlock))).Count
    $Lines = [regex]::Split($Text, "`r?`n")
    $FlagLines = @($Lines | Where-Object {
        $_ -match ("^[ `t]*SetEnv[ `t]+[^#]*" + [regex]::Escape($FlagName) + "[^#]*$")
    }).Count
    $ExactFlagLines = @($Lines | Where-Object { $_.Trim() -eq $Directive }).Count
    $SkipFlagLines = @($Lines | Where-Object {
        $_ -match ("^[ `t]*SetEnv[ `t]+[^#]*" + [regex]::Escape($SkipFlagName) + "[^#]*$")
    }).Count
    $ExactSkipLines = @($Lines | Where-Object { $_.Trim() -eq $SkipDirective }).Count
    $ExactCombinedLines = @($Lines | Where-Object { $_.Trim() -eq $CombinedDirective }).Count
    if ($BeginCount -eq 0 -and $EndCount -eq 0 -and $FlagLines -eq 0 -and $SkipFlagLines -eq 0) {
        $BlockState = "absent"
    } elseif ($BeginCount -eq 1 -and $EndCount -eq 1 -and $ExactCount -eq 1 -and
        $FlagLines -eq 1 -and $SkipFlagLines -eq 1 -and
        $ExactCombinedLines -eq 1) {
        $BlockState = "exact"
    } elseif ($BeginCount -eq 1 -and $EndCount -eq 1 -and $SplitExactCount -eq 1 -and
        $FlagLines -eq 1 -and $ExactFlagLines -eq 1 -and
        $SkipFlagLines -eq 1 -and $ExactSkipLines -eq 1) {
        $BlockState = "split_exact"
    } elseif ($BeginCount -eq 1 -and $EndCount -eq 1 -and $LegacyExactCount -eq 1 -and
        $FlagLines -eq 1 -and $ExactFlagLines -eq 1 -and $SkipFlagLines -eq 0) {
        $BlockState = "legacy_exact"
    } else {
        $BlockState = "conflict"
    }
    $Service = Get-Service -Name "sshd" -ErrorAction Stop
    $ServiceInfo = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    & $SshdPath -t -f $ConfigPath *> $null
    $SyntaxPass = $LASTEXITCODE -eq 0
    return @{
        bytes = $Bytes
        text = $Text
        newline = $Newline
        block = $Block
        splitBlock = $SplitBlock
        legacyBlock = $LegacyBlock
        blockState = $BlockState
        hash = Get-Sha256 $Bytes
        serviceRunning = $Service.Status -eq "Running"
        startupAutomatic = $ServiceInfo.StartMode -eq "Auto"
        syntaxPass = $SyntaxPass
        acl = Get-Acl -LiteralPath $ConfigPath
    }
}

function Protect-StateDirectory {
    if (-not (Test-Path -LiteralPath $StateDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    }
    & icacls.exe $StateDirectory /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" *> $null
    if ($LASTEXITCODE -ne 0) { Block "state_acl_failed" }
}

function Test-Candidate([byte[]] $Bytes, $Acl) {
    $Temporary = "$ConfigPath.$ProfileName.tmp"
    if (Test-Path -LiteralPath $Temporary) { Block "stale_config_temporary" }
    try {
        [IO.File]::WriteAllBytes($Temporary, $Bytes)
        Set-Acl -LiteralPath $Temporary -AclObject $Acl
        & $SshdPath -t -f $Temporary *> $null
        if ($LASTEXITCODE -ne 0) { Block "candidate_syntax_failed" }
    } finally {
        if (Test-Path -LiteralPath $Temporary) { Remove-Item -LiteralPath $Temporary -Force }
    }
}

function Replace-Config([byte[]] $Bytes, $Acl) {
    $Temporary = "$ConfigPath.$ProfileName.replace"
    $Backup = "$ConfigPath.$ProfileName.backup"
    if ((Test-Path -LiteralPath $Temporary) -or (Test-Path -LiteralPath $Backup)) {
        Block "stale_replace_artifact"
    }
    try {
        [IO.File]::WriteAllBytes($Temporary, $Bytes)
        Set-Acl -LiteralPath $Temporary -AclObject $Acl
        [IO.File]::Replace($Temporary, $ConfigPath, $Backup)
    } finally {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $Backup) {
            Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue
        }
        if ((Test-Path -LiteralPath $Temporary) -or (Test-Path -LiteralPath $Backup)) {
            throw "replace_cleanup_failed"
        }
    }
}

function Restart-SshdOrThrow {
    Restart-Service -Name "sshd" -Force
    $Deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        $Status = (Get-Service -Name "sshd").Status
    } while ($Status -ne "Running" -and [DateTime]::UtcNow -lt $Deadline)
    if ($Status -ne "Running") { throw "sshd_not_running" }
}

function Write-Receipt([string] $Commit, [string] $BeforeHash, [string] $AfterHash) {
    Protect-StateDirectory
    $Temporary = Join-Path $StateDirectory ".receipt.tmp"
    $Payload = [ordered]@{
        schema = 1
        profile = $ProfileName
        commit = $Commit
        beforeHash = $BeforeHash
        afterHash = $AfterHash
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($Temporary, $Payload + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $Temporary -Destination $ReceiptPath -Force
}

function Write-MigrationReceipt([string] $Commit, $PreviousReceipt, [string] $AfterHash) {
    Protect-StateDirectory
    $Temporary = Join-Path $StateDirectory ".receipt.tmp"
    $RollbackCommit = if ($PreviousReceipt.schema -eq 2) {
        $PreviousReceipt.previousCommit
    } else {
        $PreviousReceipt.commit
    }
    $RollbackAfterHash = if ($PreviousReceipt.schema -eq 2) {
        $PreviousReceipt.previousAfterHash
    } else {
        $PreviousReceipt.afterHash
    }
    $Payload = [ordered]@{
        schema = 2
        profile = $ProfileName
        commit = $Commit
        beforeHash = $PreviousReceipt.beforeHash
        afterHash = $AfterHash
        previousMode = "legacy_isolation"
        previousCommit = $RollbackCommit
        previousAfterHash = $RollbackAfterHash
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($Temporary, $Payload + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $Temporary -Destination $ReceiptPath -Force
}

function Get-PublicState {
    $State = Get-ConfigState
    $Receipt = Get-Receipt
    $ReceiptState = if ($null -eq $Receipt) {
        "absent"
    } elseif ($State.blockState -in @("exact", "split_exact", "legacy_exact") -and $Receipt.afterHash -eq $State.hash) {
        "exact"
    } else {
        "conflict"
    }
    return @{
        private = $State
        public = @{
            block_state = $State.blockState
            receipt_state = $ReceiptState
            service_running = $State.serviceRunning
            startup_automatic = $State.startupAutomatic
            syntax_pass = $State.syntaxPass
        }
        receipt = $Receipt
    }
}

if ($Action -notin @("prepare", "apply", "doctor", "rollback")) { Block "unknown_action" }

if ($Action -eq "prepare") {
    $Observed = Get-PublicState
    $GoodOwnership = ($Observed.public.block_state -eq "absent" -and $Observed.public.receipt_state -eq "absent") -or
        ($Observed.public.block_state -in @("exact", "split_exact", "legacy_exact") -and $Observed.public.receipt_state -eq "exact")
    $Verdict = if ($Observed.public.service_running -and $Observed.public.startup_automatic -and
        $Observed.public.syntax_pass -and $GoodOwnership) { "PASS" } else { "BLOCKED" }
    $Observed.public["verdict"] = $Verdict
    Emit-Result $Observed.public $(if ($Verdict -eq "PASS") { 0 } else { 1 })
}

if ($Action -eq "doctor") {
    $Observed = Get-PublicState
    $Verdict = if ($Observed.public.service_running -and $Observed.public.startup_automatic -and
        $Observed.public.syntax_pass -and $Observed.public.block_state -eq "exact" -and
        $Observed.public.receipt_state -eq "exact") { "PASS" } else { "BLOCKED" }
    $Observed.public["verdict"] = $Verdict
    Emit-Result $Observed.public $(if ($Verdict -eq "PASS") { 0 } else { 1 })
}

if ($Action -eq "apply") {
    if ($ExpectedCommit -notmatch $CommitPattern) { Block "invalid_commit" }
    $Observed = Get-PublicState
    if (-not $Observed.public.service_running -or -not $Observed.public.startup_automatic -or
        -not $Observed.public.syntax_pass) { Block "precondition_failed" }
    if ($Observed.public.block_state -eq "exact" -and $Observed.public.receipt_state -eq "exact") {
        if ($Observed.receipt.commit -ne $ExpectedCommit) { Block "receipt_commit_mismatch" }
        Emit-Result @{ verdict = "PASS"; apply_noop = $true; receipt_rebound = $false }
    }
    if ($Observed.public.block_state -eq "split_exact" -and $Observed.public.receipt_state -eq "exact") {
        if ($Observed.receipt.schema -ne 2 -or $Observed.receipt.previousMode -ne "legacy_isolation") {
            Block "split_receipt_mismatch"
        }
        $State = $Observed.private
        $CandidateText = $State.text.Replace($State.splitBlock, $State.block)
        $Encoding = New-Object System.Text.UTF8Encoding($false)
        $CandidateBytes = $Encoding.GetBytes($CandidateText)
        $AfterHash = Get-Sha256 $CandidateBytes
        Test-Candidate $CandidateBytes $State.acl
        try {
            Replace-Config $CandidateBytes $State.acl
            Restart-SshdOrThrow
            Write-MigrationReceipt $ExpectedCommit $Observed.receipt $AfterHash
        } catch {
            try {
                Replace-Config $State.bytes $State.acl
                Restart-SshdOrThrow
            } catch {
                Block "split_correction_failed_rollback_failed"
            }
            Block "split_correction_failed_rolled_back"
        }
        Emit-Result @{ verdict = "PASS"; apply_noop = $false; split_corrected = $true }
    }
    if ($Observed.public.block_state -eq "legacy_exact" -and $Observed.public.receipt_state -eq "exact") {
        $State = $Observed.private
        $CandidateText = $State.text.Replace($State.legacyBlock, $State.block)
        $Encoding = New-Object System.Text.UTF8Encoding($false)
        $CandidateBytes = $Encoding.GetBytes($CandidateText)
        $AfterHash = Get-Sha256 $CandidateBytes
        Test-Candidate $CandidateBytes $State.acl
        try {
            Replace-Config $CandidateBytes $State.acl
            Restart-SshdOrThrow
            Write-MigrationReceipt $ExpectedCommit $Observed.receipt $AfterHash
        } catch {
            try {
                Replace-Config $State.bytes $State.acl
                Restart-SshdOrThrow
            } catch {
                Block "migration_failed_rollback_failed"
            }
            Block "migration_failed_rolled_back"
        }
        Emit-Result @{ verdict = "PASS"; apply_noop = $false; migrated = $true }
    }
    if ($Observed.public.block_state -ne "absent" -or $Observed.public.receipt_state -ne "absent") {
        Block "ownership_conflict"
    }
    $State = $Observed.private
    $Match = [regex]::Match($State.text, "(?im)^[ `t]*Match(?:[ `t]+|$)")
    $InsertionIndex = if ($Match.Success) { $Match.Index } else { $State.text.Length }
    if ($InsertionIndex -gt 0 -and -not $State.text.Substring(0, $InsertionIndex).EndsWith($State.newline)) {
        Block "unsupported_insertion_boundary"
    }
    $CandidateText = $State.text.Substring(0, $InsertionIndex) + $State.block + $State.text.Substring($InsertionIndex)
    $Encoding = New-Object System.Text.UTF8Encoding($false)
    $CandidateBytes = $Encoding.GetBytes($CandidateText)
    $AfterHash = Get-Sha256 $CandidateBytes
    Test-Candidate $CandidateBytes $State.acl
    try {
        Replace-Config $CandidateBytes $State.acl
        if ((Get-Sha256 ([IO.File]::ReadAllBytes($ConfigPath))) -ne $AfterHash) { throw "postwrite_hash_mismatch" }
        Restart-SshdOrThrow
        & $SshdPath -t -f $ConfigPath *> $null
        if ($LASTEXITCODE -ne 0) { throw "postrestart_syntax_failed" }
        Write-Receipt $ExpectedCommit $State.hash $AfterHash
    } catch {
        try {
            Replace-Config $State.bytes $State.acl
            Restart-SshdOrThrow
        } catch {
            Block "apply_failed_rollback_failed"
        }
        Block "apply_failed_rolled_back"
    }
    Emit-Result @{ verdict = "PASS"; apply_noop = $false }
}

$Observed = Get-PublicState
if ($Observed.public.block_state -ne "exact" -or $Observed.public.receipt_state -ne "exact") {
    Block "rollback_state_mismatch"
}
$State = $Observed.private
$Receipt = $Observed.receipt
$Encoding = New-Object System.Text.UTF8Encoding($false)
if ($Receipt.schema -eq 2 -and $Receipt.previousMode -eq "legacy_isolation") {
    $CandidateText = $State.text.Replace($State.block, $State.legacyBlock)
    $CandidateBytes = $Encoding.GetBytes($CandidateText)
    if ((Get-Sha256 $CandidateBytes) -ne $Receipt.previousAfterHash) { Block "rollback_legacy_hash_mismatch" }
    Test-Candidate $CandidateBytes $State.acl
    try {
        Replace-Config $CandidateBytes $State.acl
        Restart-SshdOrThrow
        Write-Receipt $Receipt.previousCommit $Receipt.beforeHash $Receipt.previousAfterHash
    } catch {
        try {
            Replace-Config $State.bytes $State.acl
            Restart-SshdOrThrow
        } catch {
            Block "rollback_failed_restore_failed"
        }
        Block "rollback_failed_restored_managed_state"
    }
    Emit-Result @{ verdict = "PASS"; rollback = "legacy_restored" }
}
$CandidateText = $State.text.Replace($State.block, "")
$CandidateBytes = $Encoding.GetBytes($CandidateText)
if ((Get-Sha256 $CandidateBytes) -ne $Receipt.beforeHash) { Block "rollback_hash_mismatch" }
Test-Candidate $CandidateBytes $State.acl
try {
    Replace-Config $CandidateBytes $State.acl
    Restart-SshdOrThrow
    Remove-Item -LiteralPath $ReceiptPath -Force
} catch {
    try {
        Replace-Config $State.bytes $State.acl
        Restart-SshdOrThrow
    } catch {
        Block "rollback_failed_restore_failed"
    }
    Block "rollback_failed_restored_managed_state"
}
Emit-Result @{ verdict = "PASS"; rollback = "complete" }
