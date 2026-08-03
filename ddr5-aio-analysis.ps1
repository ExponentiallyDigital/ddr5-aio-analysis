<#######################################################################
 ddr5-aio-analysis.ps1

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.
If not, see https://www.gnu.org/licenses/.

Copyright (C) 2026 Andrew Newbury, Exponentially Digital.
########################################################################

 .SYNOPSIS
 Extracts candidate corrupted-memory addresses from these dump types and correlates the resulting
 physical addresses, both exact matches and near misses, across multiple dump files:
  
   KERNEL_SECURITY_CHECK_FAILURE (0x139) - 4 historical incidences, 6 retained dumps
   IRQL_NOT_LESS_OR_EQUAL (a) - 11 historical incidences, 1 retained dump
   SECURE_KERNEL_ERROR (18b) - 6 historical incidences, 1 retained dumps  - low confidence; see v0.3.0 notes below
   SYSTEM_SERVICE_EXCEPTION (0x3b) - 7 historical incidences, 3 retained dump
   CRITICAL_PROCESS_DIED (ef) - 3 historical incidences, 1 retained dumps 
   MEMORY_MANAGEMENT (0x1a) - 3 historical incidences, 1 retained dump
   SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7e) - 1 historical incidences, 1 retained dump
   WINLOGON_FATAL_ERROR (0xc000021a) - 1 historical incidences, 1 retained dump

  Does not cater for:
   FAULTY_HARDWARE_CORRUPTED_PAGE (12b) - 1 historical occurence, 0 retained dumps
   HYPERVISOR_ERROR (20001) - 1 historical occurence, 0 retained dumps

. PARAMETERS 
.\ddr5-aio-analysis.ps1 `
    [-DumpFolder "C:\CrashDumps"] `
    [-OutputFolder "C:\CrashDumps\Analysis"] `
    [-ProximityThresholdBytes 0x1000] `
    [-VerboseOnTimeout] `

  -CDB and -SymbolPath - only need overriding if your WinDbg install isn't in your path or your symbol cache lives somewhere other than the default, see README.md
  -ProximityThresholdBytes - controls how close two physical addresses from different dumps have to be to count as a near-match (default `0x10000`; tighten this as your dump count grows, since a wide threshold on a large dump set produces a lot of coincidental pairings, see README.md.
 -VerboseOnTimeout - displays all raw output from `cdb.exe` for use in situations where cdb execution exceeds 240s.

.BACKLOG
  - add 0x200001and 0x12b stop code(s)
  - FIX overflow when processing FullDump_20260725_081904-a_IRQL_NOT_LESS_OR_EQUAL.dmp
    error is: "Exception calling "ToInt64" with "2" argument(s): "Value was either too
    large or too small for a UInt64."
  
.NOTES
.VERSION
v0.6.1 Fixed a crash: two call sites used Hex-ToInt64 directly instead of
  Try-HexToInt64 - the exclusion filter (Where-Object over $candidateVAs)
  and the per-candidate loop's $vaInt assignment. Convert.ToInt64 throws
  OverflowException on some malformed hex strings, and an uncaught
  exception inside a Where-Object filter halts the whole pipeline
  enumeration at that point rather than just skipping the offending item -
  seen live on a 0xa dump where this silently truncated ~26 candidates
  down to 1. Both sites now use Try-HexToInt64 and explicitly skip
  unparseable candidates instead of aborting; PhysicalInt assignments
  (built from our own well-formed hex strings, lower risk but same class
  of call) were hardened the same way for consistency.
v0.6.0 Two fixes, both prompted by a direct question about whether step 6
  of the execution-logic summary (module-range filtering) was discarding
  candidates it shouldn't, and whether Windows actually hands us a
  corrupted address for every code the way it does for 0x1a's subtype
  0x41790.

  Fix 1: Is-InAnyModule was excluding any candidate whose VA fell
  ANYWHERE within a loaded module's [start,end) range from lm - but that
  range covers a module's entire image, code AND data sections alike.
  This correctly dropped return addresses and rip (code, uninteresting),
  but also silently dropped legitimate driver DATA (globals, cached
  pointers, static tables) sitting in the same module - exactly the kind
  of place real corruption could land. Replaced with exact-value
  exclusion: only rip (from TRAP_FRAME/CONTEXT) and each STACK_TEXT
  frame's specific return address are excluded now, via a new
  Get-CandidatesFromStackTextLines that parses STACK_TEXT column-by-
  column (ChildSP / RetAddr / four Args / symbol) instead of broad-
  scanning every hex token on the line - the same class of fix as the
  dps address-column bug fixed earlier, just for STACK_TEXT's ChildSP and
  RetAddr columns. A candidate that still falls within a module's range
  is no longer discarded; Get-ModuleNameForVA now tags it with which
  module instead, so the reader can weigh it rather than never seeing it.

  Fix 2: introduced a third tier, "FaultTargetAddress", for values
  Windows explicitly computed and reported as the address a faulting
  access referenced - stronger than a value merely found nearby
  (ContextPointer), but not asserted by Microsoft to BE the corrupted
  page the way 0x1a subtype 0x41790's computed PFN is
  (ConfirmedPhysicalFault) - a faulting access can validly target a
  perfectly healthy page that a corrupted POINTER merely pointed at, so
  this tier is evidence of relevance, not proof of a physical defect.
  Populated two ways: an unconditional search of !analyze -v's own output
  for "Attempt to (read|write|execute) from address X" (the exact line
  Windows prints from an access-violation EXCEPTION_RECORD - present for
  0x7e, absent for 0x3b which has no separate exception record, and
  absent for 0x139 whose FAST_FAIL exception carries no memory-address
  parameter), and 0xa's Arg1 ("memory referenced"), which was already
  being added as a candidate but had never been tagged above the generic
  ContextPointer tier despite being an equally explicit, Windows-reported
  value.
v0.5.0 Two changes, both prompted by the same run producing different
  candidate counts (35 vs 28, 52 vs 50, etc.) across two back-to-back
  executions over the identical dump folder with no script changes
  between them:

  1. Diagnostics.csv: every cdb call in this script (`!analyze -v`, `lm`,
     the supplementary `dps`, the 0x1a `dq nt!MmPfnDatabase`/`?? sizeof`
     pair, and every per-candidate `!pte`) already had its own timeout,
     but a timeout on any of them beyond !analyze -v was previously either
     silent or only logged to the console, not attributed anywhere. Since
     candidate-count drift between runs on identical input is the
     signature of a call landing on one side of a timeout under variable
     system/symbol-cache load, each dump now tracks how many of its cdb
     calls timed out and this is written to Diagnostics.csv alongside the
     raw !analyze -v line count and final candidate count. A run with any
     timeouts also now prints an explicit warning rather than leaving the
     person to notice a discrepancy after the fact. This doesn't remove
     the underlying timing variance (that's inherent to shelling out to
     cdb repeatedly under load) but it means a count difference between
     two runs is now attributable to a specific call instead of looking
     like unexplained noise in the physical-address correlation.

  2. Tier field + split correlation: every candidate previously went into
     one flat correlation pass regardless of source. But only the 0x1a
     subtype 0x41790 computed-PFN candidate is actually documented by
     Microsoft as the corrupted physical page itself - every other
     candidate (stack/register values run through !pte) is a pointer that
     merely references some kernel structure at the time of the crash,
     which is expected to recur across dumps for common bookkeeping
     objects regardless of any DRAM defect. Results are now tagged
     Tier = "ConfirmedPhysicalFault" or "ContextPointer", a new
     ConfirmedPhysicalFault-Candidates.csv holds only the former, and
     correlation now runs twice via the new Write-PhysicalCorrelation
     function: once restricted to the confirmed tier (genuine fault-
     recurrence evidence) and once over the full set (kept for reference,
     explicitly labelled as not fault-location evidence on its own). This
     replaces the single PhysicalAddress-Correlations.csv/-NearMatches.csv
     pair that previously mixed both meanings together.
v0.4.3 Added version display at commencement, console screenshot saved to
  the current directory, and displays script runtime at script completion.
v0.4.2 Added -AnalyzeTimeoutSeconds (default 240, unchanged). A dump that
  crashed in an unusually symbol-heavy process context (eg explorer.exe
  pulling in the full Windows Shell/XAML/CoreMessaging stack - 100+
  modules needing first-time PDB downloads) can genuinely take longer
  than 240s for !analyze -v to complete on a cold local symbol cache,
  with nothing actually hung. This isn't a process-handling bug: a bare
  cdb run of the identical .symfix/.reload /f/!analyze -v/lm sequence,
  with no timeout at all, completed successfully but slowly on such a
  dump. Bumping this parameter for a specific heavy dump (or just
  re-running once the local symbol cache is warm) resolves it without
  editing the script.
v0.4.1 Added -VerboseOnTimeout switch. When a cdb call times out, this
  echoes the full raw stdout/stderr captured before the kill straight to
  the console - unfiltered, including the noisy symbol-load dots and any
  retry spam that would normally be stripped out. Useful for diagnosing
  why one specific dump hangs (eg a corrupt module list) while another
  dump of the same bugcheck code processes cleanly, without needing to
  re-run manually in a separate cdb session.
v0.4.0 Added 0xc000021a (WINLOGON_FATAL_ERROR). Not exception-based (no
  TRAP_FRAME/CONTEXT block). Arg1 is documented ("string that identifies
  the problem") and a genuine kernel VA, so it's added as a candidate like
  0xef/0xa's documented arguments. Arg2 is the interesting case: it's the
  NTSTATUS error code, not an address, but a sign-extended 32-bit NTSTATUS
  (ffffffffc0000005-style) happens to satisfy the canonical-kernel-VA
  pattern by pure coincidence and commonly reappears in STACK_TEXT as one
  of KeBugCheckEx's own restated arguments - this needed its own exclusion
  branch that drops P2-P4 but deliberately protects P1, since blanket-
  excluding all of P1-P4 (as done for the exception-based codes) would
  have discarded the one genuinely useful candidate. Arg3/Arg4 are
  typically user-mode addresses in this dump's own process - out of scope
  for this pipeline's kernel-only !pte translation, and not attempted.
v0.3.0 Added 0xa and 0x18b, and fixed a wording bug: the "no TRAP_FRAME/
  CONTEXT block" message was hardcoded to name "0x1a" even when the dump
  was actually 0xef. It's now derived from $ExceptionBasedBugChecks
  membership instead of naming specific codes, so it's correct for any
  code added in future too.

  0xa (IRQL_NOT_LESS_OR_EQUAL) fits the same pattern as 0x139/0x3b/0x7e -
  real documented arguments, genuine TRAP_FRAME block - so it's simply
  added to $ExceptionBasedBugChecks. Arg1 ("memory referenced") is also
  explicitly added as a candidate like 0xef's Arg1/Arg3, though it's
  commonly too short/non-canonical to pass Is-KernelVA for this bugcheck
  (frequently a near-NULL dereference), which is the correct outcome.

  0x18b (SECURE_KERNEL_ERROR) is NOT exception-based (no TRAP_FRAME/
  CONTEXT block) and, unlike every other code here, !analyze -v gives NO
  argument descriptions for it at all - Microsoft's public documentation
  is genuinely thin. Arg2/Arg3 look like an NTSTATUS code and a faulting
  instruction address by pattern-matching against 0x3b/0x7e's format and
  this dump's own FAILURE_BUCKET_ID, but that's an inference, not a
  confirmed fact, so they are deliberately NOT auto-added as candidates
  the way 0x1a/0xef's documented arguments were. Candidates for this code
  come from STACK_TEXT only and are tagged with a low-confidence Note.
v0.2.0 Verification pass against real dump output (139/3b/7e/ef samples)
  confirmed the v0.1.9 fix: every OLD physical address exactly matched the
  PXE-level artifact, every corrected leaf PFN was unrelated to it and to
  each other. Also rewrote 0x1a subtype 0x41790: Arg2 is not a VA, so
  running !pte on it (as earlier versions did) only ever produced the PFN
  database's own backing page - the same class of bookkeeping artifact as
  the PXE bug. The correct corrupted PFN is computed directly as
  (Arg2 - MmPfnDatabase) / sizeof(_MMPFN). Confirmed the large-page case
  (0xef, 0x3b samples) is handled correctly by the existing "last pfn
  match" logic with no extra code needed - see Get-PfnFromPte.
v0.1.9 CRITICAL FIX: Get-PfnFromPte was reading the FIRST "pfn" value on
  !pte's output line, which for a normal 4-level x64 translation is the
  PXE (top-level PML4 table's own physical page), not the PTE (the actual
  leaf entry mapping the target VA to physical memory). Every physical
  address this script has ever produced before this version should be
  considered unverified - re-run the full dump set before trusting any
  further exclusion ranges. See Get-PfnFromPte for full reasoning.
v0.1.8 Fix ($ExceptionBasedBugChecks -contains $bugCheckCode) for 0xef
v0.1.7 Added CRITICAL_PROCESS_DIED (ef) analysis (same processing as 0x1a)
v0.1.6 Added 0x1a, which does not fit the other three codes' pattern:

  0x139/0x3b/0x7e all reach KeBugCheckEx via an exception, so !analyze -v
  always prints a TRAP_FRAME:/CONTEXT: register block and P2-P4 are always
  debugger bookkeeping addresses (trap frame / exception record / context
  record) - safe to exclude uniformly, as v6 does.

  0x1a is raised directly by the memory manager when it detects corruption,
  with no exception involved, so there is usually no TRAP_FRAME:/CONTEXT:
  block at all. Worse, per Microsoft's own documentation "any other values
  for parameter 1 must be individually examined" - Arg1 selects a subtype,
  and Arg2-Arg4's meaning is entirely different per subtype (an address in
  some cases, a count in others). Blanket-excluding P2-P4 the way v6 does
  for the other codes would be wrong here, since for some subtypes Arg2 IS
  the payload, not bookkeeping.

  This script only special-cases the one subtype in the request (Arg1 =
  0x41790, "a page table page has been corrupted"), where Arg2 is
  documented as the address of the PFN-database entry for the corrupted
  page table page (64-bit OS semantics only - this pipeline assumes x64
  throughout anyway). That address is added as a real candidate rather
  than excluded, and is tagged with a Note explaining an important caveat:
  its !pte-derived physical address is the PFN database entry's own
  backing page, not the corrupted page table page itself - useful as a
  correlation fingerprint, not as the fault location directly.

  For any other 0x1a Arg1 value, Arg2-Arg4 are NOT auto-added as
  candidates, since their meaning is unverified for that subtype. A
  console warning names the subtype and says it needs manual checking
  against Microsoft's bugcheck reference before extending this script to
  cover it.
 
.AUTHOR
    Andrew Newbury, Exponentially Digital (with significant help from Claude Code).
#>

param(
    [Parameter(Mandatory)]
    [string]$DumpFolder,
    [Parameter(Mandatory)]
    [string]$OutputFolder,
    [string]$CDB = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    [string]$SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
    [int64]$ProximityThresholdBytes = 0x10000,
    [switch]$VerboseOnTimeout,
    [int]$AnalyzeTimeoutSeconds = 240,
    [switch]$NoClearScreen
)

# --- START OF SCRIPT --
if (-not $NoClearScreen) { Clear-Host }
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Execution header display
$scriptPath = $PSCommandPath
if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }

# Extract the version digits (e.g., 0.4.3) from the line after .VERSION
$scriptVersion = "Unknown"
if (Test-Path $scriptPath) {
    $rawContent = Get-Content $scriptPath -Raw
    if ($rawContent -match '\.VERSION\s*[\r\n]+\s*v?(\d+\.\d+\.\d+)') {
        $scriptVersion = $Matches[1]
    }
}

# Get file write time
$scriptTime = if (Test-Path $scriptPath) { (Get-Item $scriptPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }

# display program (green) version ( yellow) and timestamp (grey)
$e = [char]27
Write-Host "`n$e[32mddr5-aio-analysis.ps1$e[0m $e[33mv$scriptVersion$e[0m $e[90m($scriptTime)$e[0m`n"

# Display parameters used
Write-Host "Active command line parameters:" -ForegroundColor DarkCyan
if ($PSBoundParameters.Count -gt 0) {
    foreach ($kvp in $PSBoundParameters.GetEnumerator()) {
        if ($kvp.Value -is [switch]) {
            # Display switch parameters cleanly (e.g., -VerboseOnTimeout)
            if ($kvp.Value) { Write-Host "  -$($kvp.Key)" -ForegroundColor Gray }
        } else {
            # Display key-value parameters
            Write-Host "  -$($kvp.Key) : $($kvp.Value)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "  (None - running with default values)" -ForegroundColor Gray
}

Write-Host "`nExecution started at $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))" 
Write-Host "--------------------------------------------"

# supported crash dump types
$SupportedBugChecks = @("0x139", "0x3b", "0x7e", "0x1a", "0xef", "0xa", "0x18b", "0xc000021a")
$ExceptionBasedBugChecks = @("0x139", "0x3b", "0x7e", "0xa")

# Known, verified 0x1a Arg1 subtypes. Key is the lowercased, zero-stripped
# hex value of Arg1. Extend only after checking Microsoft's bugcheck
# reference for the subtype's actual Arg2-Arg4 semantics.
$KnownMemoryManagementSubtypes = @{
    "41790" = "A page table page has been corrupted. Arg2 is the address of the PFN-database entry for the corrupted page table page (64-bit OS)."
}

# A hex token is exactly 16 digits, optionally split by one backtick after
# the 8th digit (cdb's own formatting), and must not be adjacent to more
# hex/backtick characters - prevents matching a fragment of a longer run.
$HexTokenCore = '[0-9a-fA-F]{8}`[0-9a-fA-F]{8}|[0-9a-fA-F]{16}'
$HexTokenPattern = "(?<![0-9a-fA-F``])($HexTokenCore)(?![0-9a-fA-F``])"

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Returns @{ Lines = [string[]]; TimedOut = [bool] }. Never discards
# whatever was captured before a forced kill.
function Invoke-Cdb {
    param(
        [string]$DumpPath,
        [string]$Commands,
        [int]$TimeoutSeconds = 120
    )
    $arguments = "-z `"$DumpPath`" -y `"$SymbolPath`" -c `"$Commands; q`""
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CDB
    $psi.Arguments = $arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $stdoutBuilder = New-Object System.Text.StringBuilder
    $stderrBuilder = New-Object System.Text.StringBuilder

    $outEvent = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    } -MessageData $stdoutBuilder

    $errEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    } -MessageData $stderrBuilder

    $timedOut = $false
    try {
        $proc.Start() | Out-Null
        try { $proc.StandardInput.Close() } catch { }
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()

        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            $timedOut = $true
            Write-Host "    [TIMEOUT] cdb exceeded ${TimeoutSeconds}s - killing it, using whatever output was captured so far." -ForegroundColor DarkYellow
            try { $proc.Kill() } catch { }
            $proc.WaitForExit(5000) | Out-Null

            # -VerboseOnTimeout dumps everything cdb had actually printed up
            # to the moment it was killed - unfiltered, including the noisy
            # symbol-load dots and retry spam that Invoke-Cdb's return value
            # normally strips out. That's exactly the detail that matters
            # when diagnosing WHY a specific dump hangs (eg a corrupt module
            # list sending cdb into a GetContextState retry loop) versus
            # another dump of the same bugcheck code processing cleanly.
            if ($VerboseOnTimeout) {
                Write-Host "    ----- BEGIN raw cdb stdout captured before timeout -----" -ForegroundColor Magenta
                Write-Host $stdoutBuilder.ToString()
                Write-Host "    ----- END raw cdb stdout -----" -ForegroundColor Magenta
                $stderrText = $stderrBuilder.ToString()
                if ($stderrText.Trim().Length -gt 0) {
                    Write-Host "    ----- BEGIN raw cdb stderr captured before timeout -----" -ForegroundColor Magenta
                    Write-Host $stderrText
                    Write-Host "    ----- END raw cdb stderr -----" -ForegroundColor Magenta
                }
            }
        }
    } finally {
        Unregister-Event -SourceIdentifier $outEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue
        Remove-Job -Name $outEvent.Name -Force -ErrorAction SilentlyContinue
        Remove-Job -Name $errEvent.Name -Force -ErrorAction SilentlyContinue
    }

    $out = $stdoutBuilder.ToString()
    $lines = ($out -split "`r`n|`n") |
        Where-Object { $_ -notmatch 'NatVis|Debugger Extension|Repository|Preparing|Waiting|Microsoft \(R\)|Loading Dump|Symbol search|Executable search|Windows 10 Kernel|Product:|Edition build|Kernel base|Debug session|System Uptime|Loading Kernel|Loading User|Loading unloaded|For analysis|kd>|quit:' } |
        ForEach-Object { $_.TrimEnd() } |
        Where-Object { $_ -ne '' }

    return [PSCustomObject]@{ Lines = @($lines); TimedOut = $timedOut }
}

function Get-HexClean([string]$hex) {
    if (-not $hex) { return $null }
    return ($hex -replace '`', '').Trim()
}

function Is-ZeroOrEmpty([string]$hex) {
    if (-not $hex) { return $true }
    $clean = (Get-HexClean $hex) -replace '^0x'
    return ($clean -match '^0+$')
}

function Is-KernelVA([string]$hex) {
    $clean = (Get-HexClean $hex) -replace '^0x', ''
    $clean = $clean.ToLower()
    if ($clean.Length -lt 12) { return $false }
    return ("0x$clean") -match '^0xffff[89a-f][0-9a-f]{11}$'
}

function Hex-ToInt64([string]$hex) {
    $clean = (Get-HexClean $hex) -replace '^0x'
    return [Convert]::ToInt64($clean, 16)
}

# Same as Hex-ToInt64 but returns $null instead of throwing.
function Try-HexToInt64([string]$hex) {
    if (Is-ZeroOrEmpty $hex) { return $null }
    try { return Hex-ToInt64 $hex } catch { return $null }
}

# Lowercased, zero-stripped hex string - used as a lookup key for the
# 0x1a subtype table, since BUGCHECK_P1 is printed without padding.
function Normalize-HexForLookup([string]$hex) {
    if (-not $hex) { return "" }
    $clean = ((Get-HexClean $hex) -replace '^0x').ToLower().TrimStart('0')
    if ($clean -eq "") { return "0" }
    return $clean
}

function Get-PfnFromPte([string[]]$pteLines) {
    $raw = $pteLines -join "`n"

    # If the VA isn't currently backed by a physical page (paged out,
    # demand-zero, decommitted, etc), there is no real PA to report for it
    # at this snapshot. Don't fall back to a shallower paging level's PFN
    # in this case - that would silently substitute the wrong page.
    if ($raw -match '(?i)not valid|invalid PTE|Pte is zero') { return $null }

    $pfnMatches = [regex]::Matches($raw, '(?im)pfn\s+([0-9a-f]+)')
    if ($pfnMatches.Count -eq 0) { return $null }

    # !pte prints one "pfn" per paging level walked on a single line - up
    # to four for a normal 4KB page (PXE, PPE, PDE, PTE, left to right).
    # Every level except the last is the PFN of a paging STRUCTURE (the
    # PML4/PDPT/PD table itself), which is shared across huge swathes of
    # unrelated address space and has nothing to do with where the VA's
    # actual data lives. Only the LAST match - the leaf entry - maps to
    # the physical page backing the VA. The previous version of this
    # function anchored on line-start and only ever matched the FIRST
    # "pfn" token, which for any 4-level walk is the PXE, not the PTE -
    # systematically wrong for every candidate except a bare top-level
    # paging structure address.
    #
    # Confirmed against real large-page candidates (0xef and 0x3b dumps,
    # July 2026 verification pass): when the leaf is a 2MB/1GB large page,
    # !pte appends a separate "LARGE PAGE pfn <hex>" line with the VA's
    # offset already folded in by WinDbg. That line also contains the word
    # "pfn" and appears after the raw PDE/PPE-as-leaf value, so taking the
    # LAST match picks it up automatically - no separate large-page handling
    # needed, and the existing (pfn*0x1000)+(VA&0xFFF) math downstream is
    # already correct for it.
    return $pfnMatches[$pfnMatches.Count - 1].Groups[1].Value
}

function PFN-To-Physical([string]$pfnStr, [string]$va) {
    try {
        $pfn = Hex-ToInt64 $pfnStr
        $vaInt = Hex-ToInt64 $va
        return "0x{0:X}" -f (($pfn * 0x1000) + ($vaInt -band 0xFFF))
    } catch { return $null }
}

function Get-ModuleRangesFromLines([string[]]$lmLines) {
    $ranges = @()
    foreach ($line in $lmLines) {
        if ($line -match '^\s*([0-9a-fA-F`]{8,17})\s+([0-9a-fA-F`]{8,17})\s+(\S+)') {
            try {
                $start = Hex-ToInt64 $Matches[1]
                $end   = Hex-ToInt64 $Matches[2]
                $ranges += [PSCustomObject]@{ Start = $start; End = $end; Name = $Matches[3] }
            } catch { }
        }
    }
    return $ranges
}

function Is-InAnyModule([int64]$vaInt, $moduleRanges) {
    foreach ($r in $moduleRanges) {
        if ($vaInt -ge $r.Start -and $vaInt -le $r.End) { return $true }
    }
    return $false
}

# v0.6.0: no longer used to discard candidates outright (see main loop) -
# a module's [start,end) range from lm covers its ENTIRE image, code and
# data alike, so blanket-discarding anything in that range also discarded
# legitimate driver data (globals, cached pointers, static tables) sitting
# in the same module - exactly the kind of place real corruption could
# land. Used now only to TAG a surviving candidate with which module it
# falls inside, as information for the reader rather than a silent filter.
function Get-ModuleNameForVA([int64]$vaInt, $moduleRanges) {
    foreach ($r in $moduleRanges) {
        if ($vaInt -ge $r.Start -and $vaInt -le $r.End) { return $r.Name }
    }
    return $null
}

# Pulls lines from a marker up to a stop pattern or maxLines, whichever
# comes first. Used to read register/stack data straight out of !analyze
# -v's own output rather than re-querying the debugger.
function Get-Section([string[]]$lines, [string]$startPattern, [string[]]$stopPatterns, [int]$maxLines = 20) {
    $capture = @()
    $capturing = $false
    foreach ($line in $lines) {
        if (-not $capturing) {
            if ($line -match $startPattern) { $capturing = $true; $capture += $line }
            continue
        }
        if ($capture.Count -ge $maxLines) { break }
        $stop = $false
        foreach ($sp in $stopPatterns) { if ($line -match $sp) { $stop = $true; break } }
        if ($stop) { break }
        $capture += $line
    }
    return $capture
}

# Broad scan using the strict 16-digit hex token pattern.
function Get-CandidatesFromLines([string[]]$lines, [string]$tokenPattern) {
    $found = @()
    foreach ($line in $lines) {
        $hexMatches = [regex]::Matches($line, $tokenPattern)
        foreach ($m in $hexMatches) {
            $candidate = "0x" + (Get-HexClean $m.Groups[1].Value)
            if ((Is-KernelVA $candidate) -and ($found -notcontains $candidate)) { $found += $candidate }
        }
    }
    return $found
}

# Column-aware: dps prints "<stack slot address>  <value>[ symbol]" per
# line. Only the VALUE (2nd column) is a meaningful candidate.
function Get-CandidatesFromDpsLines([string[]]$lines, [string]$tokenCore) {
    $found = @()
    $linePattern = "^\s*(?:$tokenCore)\s+($tokenCore)(?:\s|$)"
    foreach ($line in $lines) {
        if ($line -match $linePattern) {
            $candidate = "0x" + (Get-HexClean $Matches[1])
            if ((Is-KernelVA $candidate) -and ($found -notcontains $candidate)) { $found += $candidate }
        }
    }
    return $found
}

# Column-aware: STACK_TEXT prints "ChildSP RetAddr : Arg1 Arg2 Arg3 Arg4 :
# symbol" per frame. ChildSP is just where the frame lives (same reasoning
# as excluding dps's address column - it's a location, not a value).
# RetAddr is a call site - code, not data. Only Arg1-4 are real candidate
# values (a corrupted pointer could easily show up as one of a function's
# own arguments). Returns both sets separately so RetAddr can be excluded
# precisely by exact value later, rather than by discarding anything that
# merely falls within the same module's overall address range (v0.6.0 -
# see Get-ModuleNameForVA).
function Get-CandidatesFromStackTextLines([string[]]$lines, [string]$tokenCore) {
    $args = @()
    $retAddrs = @()
    $linePattern = "^\s*($tokenCore)\s+($tokenCore)\s*:\s*($tokenCore)\s+($tokenCore)\s+($tokenCore)\s+($tokenCore)\s*:"
    foreach ($line in $lines) {
        if ($line -match $linePattern) {
            $retAddr = "0x" + (Get-HexClean $Matches[2])
            if ((Is-KernelVA $retAddr) -and ($retAddrs -notcontains $retAddr)) { $retAddrs += $retAddr }
            for ($g = 3; $g -le 6; $g++) {
                $candidate = "0x" + (Get-HexClean $Matches[$g])
                if ((Is-KernelVA $candidate) -and ($args -notcontains $candidate)) { $args += $candidate }
            }
        }
    }
    return [PSCustomObject]@{ Args = $args; RetAddrs = $retAddrs }
}

$dumps = Get-ChildItem -Path $DumpFolder -Filter *.dmp | Sort-Object Name
$results = @()
# Per-dump run diagnostics. This exists because candidate counts have been
# observed to differ between two runs of this script over the SAME dump
# folder (e.g. 35 vs 28 candidate VAs for one dump). Nothing in the script
# was changed between such runs, so the cause has to be timing-dependent
# cdb behaviour (cold vs warm symbol cache, system load, a call landing on
# one side of one of the several per-call timeouts below). Rather than
# silently emitting whatever came out, every timeout is now counted per
# dump and written to Diagnostics.csv, so a count discrepancy between two
# runs can be attributed to a specific timed-out call instead of treated
# as unexplained noise.
$diagnostics = @()

foreach ($dump in $dumps) {
    $dumpPath = $dump.FullName
    Write-Host "`n===== Processing $($dump.Name) =====" -ForegroundColor Yellow
    $dumpTimeoutCount = 0

    $analyzeResult = Invoke-Cdb -DumpPath $dumpPath -Commands ".symfix; .reload /f; !analyze -v" -TimeoutSeconds $AnalyzeTimeoutSeconds
    if ($analyzeResult.TimedOut) {
        $dumpTimeoutCount++
        Write-Host "  Note: !analyze -v didn't exit cleanly within $($AnalyzeTimeoutSeconds)s. Using the output captured before the kill - candidate extraction for this dump may be incomplete and may not match a re-run. See Diagnostics.csv." -ForegroundColor DarkYellow
    }
    $analyzeLines = $analyzeResult.Lines
    $joinedAnalyze = $analyzeLines -join "`n"

    $bugCheckCode = $null
    if ($joinedAnalyze -match '(?im)^BUGCHECK_CODE:\s+([0-9A-Fa-f]+)') { $bugCheckCode = "0x$($Matches[1])" }

    $p1 = $null; $p2 = $null; $p3 = $null; $p4 = $null
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P1:\s+([0-9A-Fa-f]+)') { $p1 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P2:\s+([0-9A-Fa-f]+)') { $p2 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P3:\s+([0-9A-Fa-f]+)') { $p3 = $Matches[1] }
    if ($joinedAnalyze -match '(?im)^BUGCHECK_P4:\s+([0-9A-Fa-f]+)') { $p4 = $Matches[1] }

    Write-Host "  BugCheck: $bugCheckCode  P1: $p1  P2: $p2  P3: $p3  P4: $p4"

    if (-not $bugCheckCode) {
        Write-Host "  Skipping - could not determine a bugcheck code even from partial output; dump is likely too damaged to use." -ForegroundColor Red
        continue
    }
    if ($SupportedBugChecks -notcontains $bugCheckCode) {
        Write-Host "  Skipping - $bugCheckCode is not one of the supported codes ($($SupportedBugChecks -join ', '))." -ForegroundColor DarkGray
        continue
    }

    # Bookkeeping-address exclusion is code-dependent. For 0x139/0x3b/0x7e,
    # P2-P4 are always debugger self-reference addresses (trap frame /
    # exception record / context record) and are safe to exclude uniformly.
    # For 0x1a, Arg2-P4's meaning depends entirely on the Arg1 subtype - see
    # NOTES above - so only P1 (the subtype code itself) is excluded here;
    # anything else is handled explicitly per known subtype below.
    if ($ExceptionBasedBugChecks -contains $bugCheckCode) {
        $excludedInts = @($p1, $p2, $p3, $p4) | ForEach-Object { Try-HexToInt64 $_ } | Where-Object { $null -ne $_ }
    } elseif ($bugCheckCode -eq "0x1a") {
        $excludedInts = @($p1) | ForEach-Object { Try-HexToInt64 $_ } | Where-Object { $null -ne $_ }
    } elseif ($bugCheckCode -eq "0xc000021a") {
        # Arg1 here is a genuine, documented data pointer ("string that
        # identifies the problem") and must NOT be excluded - it's added
        # as a real candidate further down. Arg2 (ffffffffc0000005-style)
        # is the dangerous one to leave in: a sign-extended 32-bit NTSTATUS
        # happens to satisfy the canonical-kernel-VA pattern purely by
        # coincidence, and it commonly reappears in STACK_TEXT as one of
        # KeBugCheckEx's own restated call arguments - the same class of
        # false positive fixed for 0x139/0x3b/0x7e's header self-reference,
        # just arriving via numeric coincidence instead of literal text.
        # Arg3/Arg4 are typically user-mode addresses for this code and
        # won't pass Is-KernelVA regardless, but are excluded here too for
        # safety in case a future dump has them in-range.
        $excludedInts = @($p2, $p3, $p4) | ForEach-Object { Try-HexToInt64 $_ } | Where-Object { $null -ne $_ }
    } else {
        $excludedInts = @()
    }

    $lmResult = Invoke-Cdb -DumpPath $dumpPath -Commands "lm"
    if ($lmResult.TimedOut) {
        $dumpTimeoutCount++
        Write-Host "  Note: lm timed out - module-range filtering will use whatever partial list was captured. A shorter module list here can leave a candidate wrongly un-excluded (or vice versa) - see Diagnostics.csv." -ForegroundColor DarkYellow
    }
    $moduleRanges = Get-ModuleRangesFromLines $lmResult.Lines
    Write-Host "  Loaded module ranges captured: $($moduleRanges.Count)"

    # Register block header: "TRAP_FRAME:" for 0x139 (.trap), "CONTEXT:" for
    # 0x3b/0x7e (.cxr). 0x1a is usually raised directly by the memory
    # manager with no exception, so this block is often absent for it -
    # that's expected, not an error.
    $regBlockLines = Get-Section -lines $analyzeLines -startPattern '^(TRAP_FRAME|CONTEXT):' -stopPatterns @('^Resetting default scope', '^EXCEPTION_RECORD:', '^BLACKBOX') -maxLines 12
    $stackTextLines = Get-Section -lines $analyzeLines -startPattern '^STACK_TEXT:' -stopPatterns @('^STACK_COMMAND:') -maxLines 40

    if ($regBlockLines.Count -eq 0) {
        if ($ExceptionBasedBugChecks -contains $bugCheckCode) {
            # This code normally DOES route through a captured exception
            # (139/3b/7e/0xa all reach KeBugCheckEx via .trap/.cxr), so a
            # missing register block here is a genuine anomaly for this
            # dump, not an expected condition - skip rather than guess.
            Write-Host "  No TRAP_FRAME/CONTEXT register block found in !analyze -v output - skipping this dump." -ForegroundColor DarkYellow
            continue
        } else {
            Write-Host "  No TRAP_FRAME/CONTEXT block (expected - $bugCheckCode doesn't route through a captured exception/context record). Continuing with STACK_TEXT and any subtype-specific arguments." -ForegroundColor DarkGray
        }
    }

    $rspValue = $null
    $ripValue = $null
    foreach ($l in $regBlockLines) {
        if ($l -match 'rsp=([0-9a-f]+)') { $rspValue = $Matches[1] }
        if ($l -match 'rip=([0-9a-f]+)') { $ripValue = $Matches[1] }
    }

    # Register block: every value here is a real register at time of fault,
    # no location/value ambiguity - broad scan is fine. STACK_TEXT: column-
    # aware, since ChildSP/RetAddr aren't candidate data (see function doc).
    $regCandidates = Get-CandidatesFromLines $regBlockLines $HexTokenPattern
    $stackParsed = Get-CandidatesFromStackTextLines $stackTextLines $HexTokenCore
    $candidateVAs = @($regCandidates + $stackParsed.Args) | Select-Object -Unique

    # Exact-value known-code set: rip (where execution was) and every
    # STACK_TEXT frame's return address (a call site). Excluded below by
    # precise value match, NOT by discarding anything that merely falls
    # within the same module's overall address range - that blunter
    # approach (pre-v0.6.0) also discarded legitimate driver DATA sitting
    # in the same module, which is exactly where real corruption could land.
    $knownCodeInts = @()
    if ($ripValue) {
        $ripInt = Try-HexToInt64 ("0x" + $ripValue)
        if ($ripInt) { $knownCodeInts += $ripInt }
    }
    foreach ($ra in $stackParsed.RetAddrs) {
        $raInt = Try-HexToInt64 $ra
        if ($raInt) { $knownCodeInts += $raInt }
    }

    # Best-effort deeper stack read (only fires if a register block gave us
    # an rsp - won't apply to most 0x1a dumps, which is fine).
    if ($rspValue -and -not (Is-ZeroOrEmpty $rspValue)) {
        $dpsResult = Invoke-Cdb -DumpPath $dumpPath -Commands "dps 0x$rspValue L16" -TimeoutSeconds 30
        if ($dpsResult.TimedOut) {
            $dumpTimeoutCount++
            Write-Host "  Note: supplementary stack dps timed out - continuing without it." -ForegroundColor DarkYellow
        }
        $extra = Get-CandidatesFromDpsLines $dpsResult.Lines $HexTokenCore
        foreach ($c in $extra) { if ($candidateVAs -notcontains $c) { $candidateVAs += $c } }
    }

    # Per-candidate tiers, separate from Notes. Defaults to ContextPointer
    # (assigned at result-build time below) unless set here to something
    # Windows explicitly computed rather than a value merely found nearby.
    $candidateTiers = @{}

    # !analyze -v prints "Attempt to read/write/execute from address X" as
    # part of an access-violation EXCEPTION_RECORD, computed by Windows
    # itself from the exception's own parameters - not a value we located
    # by scanning nearby registers/stack. Search is unconditional (not
    # gated to specific codes): it only fires if the line is actually
    # present, which in practice means access-violation-based codes like
    # 0x7e. Harmless no-op for codes that don't print it (eg 0x3b, which
    # has no separate EXCEPTION_RECORD; 0x139's FAST_FAIL exception has no
    # memory-address parameter at all).
    if ($joinedAnalyze -match '(?im)Attempt to (?:read|write|execute) from address\s+([0-9a-f]+)') {
        $faultAddr = "0x" + (Get-HexClean $Matches[1])
        if (Is-KernelVA $faultAddr) {
            if ($candidateVAs -notcontains $faultAddr) { $candidateVAs += $faultAddr }
            $candidateTiers[$faultAddr] = "FaultTargetAddress"
        }
    }

    # Per-candidate notes, for cases where a candidate's meaning needs
    # explanation beyond "found in a register/stack slot".
    $candidateNotes = @{}

    if ($bugCheckCode -eq "0x1a") {
        $subtype = Normalize-HexForLookup $p1
        if ($KnownMemoryManagementSubtypes.ContainsKey($subtype)) {
            Write-Host "  0x1a subtype $p1 recognized: $($KnownMemoryManagementSubtypes[$subtype])" -ForegroundColor Cyan
            if ($subtype -eq "41790") {
                # Arg2 is NOT a VA pointing at data - it's the address of this
                # page's entry in the PFN database array. The actual corrupted
                # PFN is that entry's INDEX, computed as:
                #   (Arg2 - MmPfnDatabase) / sizeof(_MMPFN)
                # Earlier versions of this script ran !pte on Arg2 as if it
                # were an ordinary VA, which only ever produced the physical
                # page backing the PFN database structure itself - the same
                # class of self-referential bookkeeping artifact as the PXE
                # bug fixed in v0.1.9, not the actual corrupted page. This
                # computation bypasses !pte entirely for this candidate.
                $pfnDbResult = Invoke-Cdb -DumpPath $dumpPath -Commands "dq nt!MmPfnDatabase L1" -TimeoutSeconds 30
                $mmpfnSizeResult = Invoke-Cdb -DumpPath $dumpPath -Commands "?? sizeof(nt!_MMPFN)" -TimeoutSeconds 30
                if ($pfnDbResult.TimedOut) { $dumpTimeoutCount++; Write-Host "  Note: nt!MmPfnDatabase lookup timed out." -ForegroundColor DarkYellow }
                if ($mmpfnSizeResult.TimedOut) { $dumpTimeoutCount++; Write-Host "  Note: sizeof(_MMPFN) lookup timed out." -ForegroundColor DarkYellow }

                $mmPfnDatabaseInt = $null
                foreach ($l in $pfnDbResult.Lines) {
                    if ($l -match '^\s*[0-9a-fA-F`]{8,17}\s+([0-9a-fA-F`]{8,17})') {
                        $mmPfnDatabaseInt = Try-HexToInt64 ("0x" + (Get-HexClean $Matches[1]))
                        break
                    }
                }

                # 0x30 is the documented _MMPFN size on current x64 builds -
                # used as a fallback only if the live ?? query can't be parsed.
                $mmpfnSize = 0x30
                foreach ($l in $mmpfnSizeResult.Lines) {
                    if ($l -match '0x([0-9a-fA-F]+)\s*$') {
                        $parsedSize = Try-HexToInt64 ("0x" + $Matches[1])
                        if ($parsedSize) { $mmpfnSize = $parsedSize }
                        break
                    }
                }

                $arg2Int = Try-HexToInt64 $p2
                if ($mmPfnDatabaseInt -and $arg2Int -and $arg2Int -gt $mmPfnDatabaseInt) {
                    $delta = $arg2Int - $mmPfnDatabaseInt
                    if (($delta % $mmpfnSize) -eq 0) {
                        $pfnIndex = $delta / $mmpfnSize
                        $physComputed = "0x{0:X}" -f ($pfnIndex * 0x1000)
                        Write-Host "  Computed corrupted PFN 0x$($pfnIndex.ToString('X')) -> Physical $physComputed" -ForegroundColor Cyan
                        $results += [PSCustomObject]@{
                            Dump           = $dump.Name
                            BugCheckCode   = $bugCheckCode
                            CorruptionType = $p1
                            VA             = "(computed via PFN-database index, not VA-derived)"
                            Physical       = $physComputed
                            PhysicalInt    = Try-HexToInt64 $physComputed
                            Tier           = "ConfirmedPhysicalFault"
                            Note           = "0x1a subtype 0x41790: (Arg2 - MmPfnDatabase) / sizeof(_MMPFN). Page-aligned base only - this bugcheck gives no byte offset within the page. This is the ONLY candidate type in this script that Microsoft's documentation confirms IS the corrupted physical page, rather than a pointer that merely refers to it."
                        }
                    } else {
                        Write-Host "  (Arg2 - MmPfnDatabase) did not divide evenly by sizeof(_MMPFN) - values may be from the wrong session. Skipping computed candidate for this dump." -ForegroundColor Red
                    }
                } else {
                    Write-Host "  Could not resolve nt!MmPfnDatabase or Arg2 for this dump - skipping computed candidate." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  0x1a subtype $p1 is not a recognized/verified subtype in this script. Per Microsoft's bugcheck reference, Arg2-Arg4 meaning differs per subtype and must be checked manually before treating them as addresses - they are NOT auto-added as candidates here." -ForegroundColor DarkYellow
        }
    }

    if ($bugCheckCode -eq "0xef") {
        foreach ($v in @($p1, $p3)) {
            $c = "0x" + (Get-HexClean $v)
            if ((Is-KernelVA $c) -and ($candidateVAs -notcontains $c)) {
                $candidateVAs += $c
                $candidateNotes[$c] = "0xef Arg1/Arg3: process/thread object involved in critical process death (not debugger bookkeeping)."
            }
        }
    }

    if ($bugCheckCode -eq "0xa") {
        # Arg1 ("memory referenced") is documented by Microsoft, so it's
        # attempted here the same way as 0xef's Arg1/Arg3 - but IRQL_NOT_
        # LESS_OR_EQUAL is very often a near-NULL or otherwise non-canonical
        # pointer dereference, so this frequently won't pass Is-KernelVA at
        # all. That's the correct, expected outcome, not a bug. Same tier as
        # the EXCEPTION_RECORD fault address above - both are Windows
        # explicitly reporting "this is the address that was accessed", not
        # a value we merely found nearby.
        $c = "0x" + (Get-HexClean $p1)
        if ((Is-KernelVA $c) -and ($candidateVAs -notcontains $c)) {
            $candidateVAs += $c
            $candidateNotes[$c] = "0xa Arg1: memory referenced at time of the fault (not debugger bookkeeping)."
            $candidateTiers[$c] = "FaultTargetAddress"
        }
    }

    if ($bugCheckCode -eq "0x18b") {
        # Unlike every other code handled here, !analyze -v gives NO
        # argument descriptions at all for 0x18b - Microsoft's public
        # documentation is genuinely thin. Arg2 (ffffffffc0000005-pattern)
        # resembles the NTSTATUS access-violation code seen in 0x3b/0x7e,
        # and Arg3 looks like a faulting instruction address (consistent
        # with this dump's own FAILURE_BUCKET_ID naming a function+offset),
        # but that's an inference from pattern-matching, not a confirmed
        # fact. Deliberately NOT auto-added as candidates the way 0x1a/0xef
        # are, since those additions were justified by explicit Microsoft
        # documentation. Candidates for this code come from STACK_TEXT
        # only, and are tagged below so they're visibly lower-confidence.
        Write-Host "  0x18b (SECURE_KERNEL_ERROR): Arg1-Arg4 aren't officially documented by Microsoft. Arg2/Arg3 look like an exception code and faulting instruction address by pattern, but that's inferred, not confirmed - not auto-added as candidates. Relying on STACK_TEXT only." -ForegroundColor DarkYellow
    }

    if ($bugCheckCode -eq "0xc000021a") {
        # Arg1 ("string that identifies the problem") is documented and
        # genuinely a kernel-space pointer - added the same way as 0xef's
        # Arg1/Arg3 and 0xa's Arg1.
        $c = "0x" + (Get-HexClean $p1)
        if ((Is-KernelVA $c) -and ($candidateVAs -notcontains $c)) {
            $candidateVAs += $c
            $candidateNotes[$c] = "0xc000021a Arg1: address of the string identifying the problem (not debugger bookkeeping)."
        }
        # Arg3/Arg4 are typically user-mode addresses (this dump's own
        # values sit inside csrss.exe's own module range, per its lm
        # output) - this pipeline only translates kernel-space VAs via a
        # kernel-context !pte walk, so a user-mode address is out of scope
        # here regardless and isn't attempted.
        Write-Host "  0xc000021a: Arg3/Arg4 are typically user-mode addresses (this process's own VA space), which this pipeline can't translate the same way as kernel addresses - not attempted." -ForegroundColor DarkGray
    }

    $preExclusionCount = $candidateVAs.Count
    # Use Try-HexToInt64, not Hex-ToInt64, inside this filter. An unprotected
    # Hex-ToInt64 call that throws on one malformed candidate doesn't just
    # skip that candidate - Where-Object's default error behavior halts the
    # whole pipeline enumeration at that point, silently truncating every
    # candidate after it. A candidate that can't even be parsed to Int64 is
    # dropped explicitly here instead, and processing continues normally.
    $candidateVAs = $candidateVAs | Where-Object {
        $intVal = Try-HexToInt64 $_
        ($null -ne $intVal) -and ($excludedInts -notcontains $intVal)
    }
    $excludedCount = $preExclusionCount - $candidateVAs.Count
    if ($excludedCount -gt 0) {
        Write-Host "  Excluded $excludedCount candidate(s) matching known bookkeeping values or unparseable." -ForegroundColor DarkGray
    }

    Write-Host "  Candidate kernel VAs from fault context: $($candidateVAs.Count)"

    foreach ($va in $candidateVAs) {
        $vaInt = Try-HexToInt64 $va
        if ($null -eq $vaInt) { continue }
        # v0.6.0: only exact known-code values (rip, STACK_TEXT return
        # addresses) are excluded here - see $knownCodeInts above. A
        # candidate merely falling within a module's overall [start,end)
        # range is no longer discarded outright; that range covers a
        # module's data sections too, and blanket-excluding it threw away
        # legitimate driver data along with genuine code addresses.
        if ($knownCodeInts -contains $vaInt) { continue }

        $pteResult = Invoke-Cdb -DumpPath $dumpPath -Commands "!pte $va" -TimeoutSeconds 30
        if ($pteResult.TimedOut) {
            $dumpTimeoutCount++
            Write-Host "    [TIMEOUT] !pte $va - skipping this candidate." -ForegroundColor DarkYellow
            continue
        }
        $pfn = Get-PfnFromPte $pteResult.Lines
        if (-not $pfn) { continue }

        $phys = PFN-To-Physical $pfn $va
        if ($phys) {
            $note = ""
            if ($candidateNotes.ContainsKey($va)) {
                $note = $candidateNotes[$va]
            } elseif ($bugCheckCode -eq "0x18b") {
                $note = "0x18b argument semantics aren't officially documented by Microsoft - this candidate comes from STACK_TEXT only, not an explicitly-documented bugcheck argument. Lower confidence than other codes."
            }

            # Tag (don't discard) if this VA falls inside a loaded module's
            # image range - informational, since it could be legitimate
            # driver data (a global, cached pointer, static table) rather
            # than a false positive. The reader can weigh this themselves.
            $moduleName = Get-ModuleNameForVA $vaInt $moduleRanges
            if ($moduleName) {
                $moduleNote = "Falls within loaded module '$moduleName' image range - may be driver/module data, not necessarily unrelated to the fault."
                $note = if ($note) { "$note $moduleNote" } else { $moduleNote }
            }

            $tier = if ($candidateTiers.ContainsKey($va)) { $candidateTiers[$va] } else { "ContextPointer" }

            $results += [PSCustomObject]@{
                Dump           = $dump.Name
                BugCheckCode   = $bugCheckCode
                CorruptionType = $p1
                VA             = $va
                Physical       = $phys
                PhysicalInt    = Try-HexToInt64 $phys
                Tier           = $tier
                Note           = $note
            }
        }
    }

    $diagnostics += [PSCustomObject]@{
        Dump                = $dump.Name
        BugCheckCode        = $bugCheckCode
        AnalyzeTimedOut     = $analyzeResult.TimedOut
        AnalyzeLineCount    = $analyzeLines.Count
        FinalCandidateCount = $candidateVAs.Count
        TimeoutsEncountered = $dumpTimeoutCount
    }
    if ($dumpTimeoutCount -gt 0) {
        Write-Host "  [WARNING] $dumpTimeoutCount cdb call(s) timed out while processing this dump. Candidate counts for this dump may be incomplete and may not reproduce on a re-run under different system/symbol-cache load. See Diagnostics.csv." -ForegroundColor Red
    }
}

# Runs the exact-match + near-match physical-address correlation over a
# given subset of $results and writes "$FilePrefix-Correlations.csv" and
# "$FilePrefix-NearMatches.csv". This is called separately for the
# ConfirmedPhysicalFault tier and for the full (all-tier) candidate set,
# because the two mean different things: a match among ConfirmedPhysical-
# Fault rows means the same physical page was independently confirmed
# corrupted in more than one dump - genuine fault-recurrence evidence. A
# match among ContextPointer rows (stack/register values run through !pte)
# only means two dumps happened to reference the same kernel object/
# structure - expected for common bookkeeping structures regardless of any
# DRAM defect, and NOT fault-location evidence on its own. Conflating the
# two into a single correlation (as earlier versions of this script did)
# made every match look like the same kind of signal.
function Write-PhysicalCorrelation {
    param(
        [array]$Data,
        [string]$OutputFolder,
        [string]$FilePrefix,
        [string]$ConsoleLabel,
        [int64]$ProximityThresholdBytes
    )

    $corrCsv = Join-Path $OutputFolder "$FilePrefix-Correlations.csv"
    $nearCsv = Join-Path $OutputFolder "$FilePrefix-NearMatches.csv"

    if (-not $Data -or $Data.Count -eq 0) {
        Write-Host "`n[$ConsoleLabel] No candidates in this tier - skipping correlation." -ForegroundColor DarkGray
        "PhysicalAddress,MatchType,DumpFile,BugCheckCode,CorruptionType,VirtualAddress,OccurrenceCount,Note" | Out-File -FilePath $corrCsv -Encoding UTF8
        "PhysicalA,DumpA,BugCheckA,PhysicalB,DumpB,BugCheckB,DistanceBytes,MatchType" | Out-File -FilePath $nearCsv -Encoding UTF8
        return
    }

    Write-Host "`n----- $ConsoleLabel -----" -ForegroundColor Cyan

    # ----- Exact matches, split by whether all dumps in the group share a bugcheck code -----
    $physGroups = $Data | Group-Object Physical | Where-Object { $_.Count -gt 1 }
    if ($physGroups) {
        $corrRows = $physGroups | ForEach-Object {
            $phys = $_.Name
            $occ  = $_.Count
            $codes = $_.Group | Select-Object -ExpandProperty BugCheckCode -Unique
            $matchType = if ($codes.Count -gt 1) { "CrossCode" } else { "SameCode" }
            $_.Group | Sort-Object Dump | ForEach-Object {
                [PSCustomObject]@{
                    PhysicalAddress = $phys
                    MatchType       = $matchType
                    DumpFile        = $_.Dump
                    BugCheckCode    = $_.BugCheckCode
                    CorruptionType  = $_.CorruptionType
                    VirtualAddress  = $_.VA
                    OccurrenceCount = $occ
                    Note            = $_.Note
                }
            }
        } | Sort-Object @{Expression = { if ($_.MatchType -eq "CrossCode") { 0 } else { 1 } }}, PhysicalAddress, DumpFile
        $corrRows | Export-Csv -Path $corrCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Exact-match physical addresses across dumps saved to $corrCsv"

        $crossGroups = $physGroups | Where-Object { ($_.Group | Select-Object -ExpandProperty BugCheckCode -Unique).Count -gt 1 }
        $sameGroups  = $physGroups | Where-Object { ($_.Group | Select-Object -ExpandProperty BugCheckCode -Unique).Count -eq 1 }

        if ($crossGroups) {
            Write-Host "  CROSS-CODE matches (different failure modes sharing a physical address - strongest signal):" -ForegroundColor Magenta
            $crossGroups | ForEach-Object {
                $codes = ($_.Group | Select-Object -ExpandProperty BugCheckCode -Unique) -join '/'
                Write-Host ("    {0}  (seen in {1} dumps, codes: {2})" -f $_.Name, $_.Count, $codes) -ForegroundColor Magenta
            }
        }
        if ($sameGroups) {
            Write-Host "  Same-code matches:" -ForegroundColor DarkYellow
            $sameGroups | ForEach-Object { Write-Host ("    {0}  (seen in {1} dumps)" -f $_.Name, $_.Count) -ForegroundColor DarkYellow }
        }
    } else {
        Write-Host "No physical address recurred exactly across more than one dump."
        "PhysicalAddress,MatchType,DumpFile,BugCheckCode,CorruptionType,VirtualAddress,OccurrenceCount,Note" | Out-File -FilePath $corrCsv -Encoding UTF8
    }

    # ----- Near matches, tagged per-pair as SameCode/CrossCode -----
    $sortedByPhys = $Data | Sort-Object PhysicalInt
    $nearRows = @()
    for ($i = 0; $i -lt $sortedByPhys.Count - 1; $i++) {
        for ($j = $i + 1; $j -lt $sortedByPhys.Count; $j++) {
            $a = $sortedByPhys[$i]; $b = $sortedByPhys[$j]
            $dist = $b.PhysicalInt - $a.PhysicalInt
            if ($dist -gt $ProximityThresholdBytes) { break }
            if ($a.Dump -eq $b.Dump) { continue }
            if ($a.Physical -eq $b.Physical) { continue }
            $matchType = if ($a.BugCheckCode -eq $b.BugCheckCode) { "SameCode" } else { "CrossCode" }
            $nearRows += [PSCustomObject]@{
                PhysicalA     = $a.Physical
                DumpA         = $a.Dump
                BugCheckA     = $a.BugCheckCode
                PhysicalB     = $b.Physical
                DumpB         = $b.Dump
                BugCheckB     = $b.BugCheckCode
                DistanceBytes = $dist
                MatchType     = $matchType
            }
        }
    }
    if ($nearRows.Count -gt 0) {
        $nearRows | Sort-Object @{Expression = { if ($_.MatchType -eq "CrossCode") { 0 } else { 1 } }}, DistanceBytes |
            Export-Csv -Path $nearCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Near-match candidates (within $ProximityThresholdBytes bytes, different dumps) saved to $nearCsv"

        $crossNear = $nearRows | Where-Object { $_.MatchType -eq "CrossCode" } | Sort-Object DistanceBytes
        $sameNear  = $nearRows | Where-Object { $_.MatchType -eq "SameCode" }  | Sort-Object DistanceBytes

        if ($crossNear) {
            Write-Host "  CROSS-CODE near matches (strongest signal):" -ForegroundColor Magenta
            $crossNear | Select-Object -First 10 | ForEach-Object {
                Write-Host ("    {0} ({1}, {2})  <->  {3} ({4}, {5})   distance 0x{6:X}" -f $_.PhysicalA, $_.DumpA, $_.BugCheckA, $_.PhysicalB, $_.DumpB, $_.BugCheckB, $_.DistanceBytes) -ForegroundColor Magenta
            }
        }
        if ($sameNear) {
            Write-Host "  Same-code near matches:" -ForegroundColor DarkYellow
            $sameNear | Select-Object -First 10 | ForEach-Object {
                Write-Host ("    {0} ({1})  <->  {2} ({3})   distance 0x{4:X}" -f $_.PhysicalA, $_.DumpA, $_.PhysicalB, $_.DumpB, $_.DistanceBytes) -ForegroundColor DarkYellow
            }
        }
    } else {
        Write-Host "No near-match candidates within $ProximityThresholdBytes bytes across different dumps."
        "PhysicalA,DumpA,BugCheckA,PhysicalB,DumpB,BugCheckB,DistanceBytes,MatchType" | Out-File -FilePath $nearCsv -Encoding UTF8
    }
}

Write-Host "`n===== Fault-Context Candidate Physical Addresses ====="
if ($results.Count -gt 0) {
    $results = $results | Sort-Object Physical, Dump

    $allCsv = Join-Path $OutputFolder "FaultContext-Candidates.csv"
    $results | Select-Object Dump, BugCheckCode, CorruptionType, VA, Physical, Tier, Note |
        Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
    Write-Host "All candidates (post module-range + bookkeeping filtering) saved to $allCsv"

    $confirmed = @($results | Where-Object { $_.Tier -eq "ConfirmedPhysicalFault" })
    $confirmedCsv = Join-Path $OutputFolder "ConfirmedPhysicalFault-Candidates.csv"
    $confirmed | Select-Object Dump, BugCheckCode, CorruptionType, Physical, Note |
        Export-Csv -Path $confirmedCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Confirmed-tier candidates (documented as the actual corrupted physical page, not merely a pointer referencing it) saved to $confirmedCsv ($($confirmed.Count) row(s))"

    # Two separate correlation passes over two different meanings of "match" -
    # see the comment on Write-PhysicalCorrelation above. Only the first is
    # fault-recurrence evidence; the second is retained for reference and
    # pattern-spotting only.
    Write-PhysicalCorrelation -Data $confirmed -OutputFolder $OutputFolder -FilePrefix "ConfirmedPhysicalFault" `
        -ConsoleLabel "CONFIRMED PHYSICAL FAULT correlation - $($confirmed.Count) candidate(s); the only tier that constitutes fault-location evidence" `
        -ProximityThresholdBytes $ProximityThresholdBytes

    Write-PhysicalCorrelation -Data $results -OutputFolder $OutputFolder -FilePrefix "PhysicalAddress" `
        -ConsoleLabel "Context-pointer correlation, all tiers - $($results.Count) candidate(s); reference only, NOT fault-location evidence on its own" `
        -ProximityThresholdBytes $ProximityThresholdBytes

    $typeCsv = Join-Path $OutputFolder "CorruptionType-Summary.csv"
    $results | Select-Object Dump, BugCheckCode, CorruptionType -Unique |
        Sort-Object Dump |
        Export-Csv -Path $typeCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nPer-dump bugcheck code / P1 summary saved to $typeCsv"
} else {
    Write-Host "No fault-context candidates found in any supported dump."
}

$diagCsv = Join-Path $OutputFolder "Diagnostics.csv"
$diagnostics | Export-Csv -Path $diagCsv -NoTypeInformation -Encoding UTF8
$totalTimeouts = ($diagnostics | Measure-Object -Property TimeoutsEncountered -Sum).Sum
Write-Host "`nPer-dump run diagnostics saved to $diagCsv"
if ($totalTimeouts -gt 0) {
    Write-Host "[WARNING] $totalTimeouts cdb call(s) timed out across this run. If a re-run over the same dumps produces different candidate counts, check Diagnostics.csv first - a timeout is the most likely explanation, not a real difference in the dumps." -ForegroundColor Red
}

Write-Host "`nDone."

# --- END OF SCRIPT ---
$stopwatch.Stop()

# Format elapsed time as HH:MM:SS.fff or total seconds
$elapsed = $stopwatch.Elapsed
$formattedTime = "{0:D2}:{1:D2}:{2:D2}.{3:D3}" -f $elapsed.Hours, $elapsed.Minutes, $elapsed.Seconds, $elapsed.Milliseconds

Write-Host "--------------------------------------------"
Write-Host "Execution time: $formattedTime ($([math]::Round($elapsed.TotalSeconds, 2))s)" -ForegroundColor Yellow

# generate the timestamped filename
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$filename  = "ddr5-aio-analysis_$timestamp.txt"

# set full path to current working directory
$logFile = Join-Path -Path $PWD -ChildPath $filename

# simulate Ctrl+Shift+A (Select All) and Ctrl+Shift+C (Copy) in Windows Terminal
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("^+a")  # Ctrl+Shift+A
Start-Sleep -Milliseconds 200
[System.Windows.Forms.SendKeys]::SendWait("^+c")  # Ctrl+Shift+C
Start-Sleep -Milliseconds 300

# extract plain text clipboard content and save to file
$textContent = Get-Clipboard
if ($textContent) {
    $textContent | Out-File -FilePath $logFile -Encoding utf8
    Write-Host "`nConsole log saved as $logFile" -ForegroundColor Green
} else {
    Write-Host "`n[Warning] Clipboard contained no text data." -ForegroundColor Yellow
}
