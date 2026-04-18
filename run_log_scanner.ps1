# PowerShell script to run log scanner with interactive prompts
# Usage: powershell -ExecutionPolicy Bypass -File run_log_scanner.ps1

function Pause-Script {
    Read-Host "`nPress Enter to exit"
}

try {
    # Check Python 3 is installed
    if (-not (Get-Command python3 -ErrorAction SilentlyContinue)) {
        Write-Host "Python 3 is not installed. Please install Python 3.8+"
        Pause-Script
        exit 1
    }

    $repo_dir      = $PSScriptRoot
    $reports_dir   = Join-Path (Join-Path $HOME "Documents") "reports"
    $python_script = Join-Path (Join-Path $repo_dir "scripts") "log_scanner.py"

    # Verify the python script exists
    if (-not (Test-Path $python_script -PathType Leaf)) {
        Write-Host "Python script not found: $python_script"
        Pause-Script
        exit 1
    }

    # Create reports directory if it doesn't exist
    if (-not (Test-Path $reports_dir)) {
        New-Item -ItemType Directory -Path $reports_dir -Force | Out-Null
    }

    # Prompt for log file path
    $log_file = Read-Host "Enter path to .log file"

    if ([string]::IsNullOrWhiteSpace($log_file)) {
        Write-Host "No input file provided."
        Pause-Script
        exit 1
    }

    # Strip surrounding quotes if user dragged and dropped file into terminal
    $log_file = $log_file.Trim('"').Trim("'")

    if (-not (Test-Path $log_file -PathType Leaf)) {
        Write-Host "File not found: $log_file"
        Pause-Script
        exit 1
    }

    # Build argument list
    $py_args = [System.Collections.ArrayList]@()
    $py_args.Add($python_script) | Out-Null
    $py_args.Add($log_file) | Out-Null
    $py_args.Add("--output-dir") | Out-Null
    $py_args.Add($reports_dir) | Out-Null
    $py_args.Add("--tui") | Out-Null

    # Optional report credentials
    $report_username = Read-Host "Set report username (leave blank to disable login)"
    if (-not [string]::IsNullOrWhiteSpace($report_username)) {
        $secure_password = Read-Host "Set report password" -AsSecureString
        $bstr            = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure_password)
        $report_password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $py_args.Add("--report-username") | Out-Null
        $py_args.Add($report_username) | Out-Null
        $py_args.Add("--report-password") | Out-Null
        $py_args.Add($report_password) | Out-Null
    }

    # Optional output formats
    $formats = Read-Host "Enter output formats (json,csv,html,db) or leave blank for all"
    if (-not [string]::IsNullOrWhiteSpace($formats)) {
        $py_args.Add("--formats") | Out-Null
        $py_args.Add($formats) | Out-Null
    }

    $webChoice = Read-Host "Enable web output (DB/auth)? [y/N]"
    if ($webChoice -match '^(?i:y|yes)$') {
        $py_args.Add("--web") | Out-Null
    }

    # Debug: show the full command being run
    Write-Host "`nRunning: python3 $($py_args -join ' ')`n"

    # Call Python CLI using Start-Process to avoid splatting issues
    $process = Start-Process -FilePath "python3" -ArgumentList $py_args -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        Write-Host "`nLog scanner exited with error code: $($process.ExitCode)"
    } else {
        Write-Host "`nDone."
    }

} catch {
    Write-Host "`nUnexpected error: $_"
    Write-Host $_.ScriptStackTrace
} finally {
    Pause-Script
}