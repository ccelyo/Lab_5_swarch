# Network Segmentation checks for role 7 (Andres).
# Without arguments this runs the flat topology and then the segmented one.
# The same checks can target the team compose (Kevin / Fabian):
#
#   .\run-tests.ps1 -ComposeFile ..\docker-compose.yml -ProjectName team `
#     -OutputDir ..\evidencias\equipo -GatewayHost api -BackendHost service-a `
#     -DbHost database -Phase custom
#
# Requires a service named -AttackerService (default: attacker) on the external
# network, with curl, nmap and openssl. Internal checks use curl and openssl
# inside -GatewayService, -BackendService and -FrontendService.

[CmdletBinding()]
param(
    [string]$ComposeFile = "",
    [string]$ProjectName = "",
    [string]$OutputDir = "",
    [string]$Phase = "custom",
    [string]$GatewayHost = "gateway",
    [string]$BackendHost = "backend",
    [string]$DbHost = "db",
    [string]$AttackerService = "attacker",
    [string]$GatewayService = "gateway",
    [string]$BackendService = "backend",
    [string]$FrontendService = "frontend",
    [string]$DbService = "db",
    [int]$GatewayPort = 443,
    [int]$BackendPort = 8080,
    [int]$DbPort = 5432,
    [switch]$SkipUp,
    [switch]$SkipDown
)

$ErrorActionPreference = "Continue"
$script:DockerExe = $null
$script:HarnessFailed = $false

function Resolve-DockerExe {
    if ($script:DockerExe) { return $script:DockerExe }
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($cmd) {
        $script:DockerExe = $cmd.Source
        return $script:DockerExe
    }
    $candidates = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Docker\Docker\resources\bin\docker.exe")
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            $script:DockerExe = $candidate
            return $script:DockerExe
        }
    }
    throw "docker no esta en PATH. Instala Docker Desktop y vuelve a correr este script."
}

function Quote-WinArg([string]$Arg) {
    if ($null -eq $Arg) { return '""' }
    if ($Arg -notmatch '[\s"]') { return $Arg }
    return '"' + ($Arg -replace '"', '\"') + '"'
}

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$DockerArgs)
    $docker = Resolve-DockerExe
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $docker
    $quoted = foreach ($arg in $DockerArgs) { Quote-WinArg $arg }
    $psi.Arguments = ($quoted -join " ")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.WorkingDirectory = $PSScriptRoot
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $outTask.Wait()
    $errTask.Wait()
    $text = $outTask.Result
    $err = $errTask.Result
    if ($err) {
        if ($text -and -not $text.EndsWith("`n")) { $text += "`n" }
        $text += $err
    }
    if ($null -eq $text) { $text = "" }
    return [pscustomobject]@{ Text = $text; ExitCode = $process.ExitCode }
}

function Assert-HostToken([string]$Value, [string]$Name) {
    if ($Value -notmatch '^[A-Za-z0-9._-]+$') {
        throw "$Name contiene caracteres no permitidos: $Value"
    }
}

function Convert-ToLf([string]$Text) {
    $lf = $Text -replace "`r`n", "`n" -replace "`r", "`n"
    if (-not $lf.EndsWith("`n")) { $lf += "`n" }
    return $lf
}

function Invoke-ServiceScript {
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [Parameter(Mandatory = $true)][string]$ScriptBody
    )
    $lf = Convert-ToLf $ScriptBody
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($lf))
    $runner = "printf '%s' $b64 | base64 -d > /tmp/lab5-check.sh && sh /tmp/lab5-check.sh"
    return Invoke-Docker @(
        "compose", "-f", $ComposeFile, "-p", $ProjectName,
        "exec", "-T", $Service, "sh", "-c", $runner
    )
}

function Save-Result {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$CommandLabel,
        [Parameter(Mandatory = $true)]$Result
    )
    $path = Join-Path $OutputDir $FileName
    $body = $Result.Text
    if ($null -eq $body) { $body = "" }
    $content = "COMMAND: $CommandLabel`r`n`r`n$body"
    if (-not $content.EndsWith("`n")) { $content += "`r`n" }
    $content += "`r`nEXIT_CODE: $($Result.ExitCode)`r`n"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($path, $content, $utf8)
    Write-Host "saved $FileName (exit $($Result.ExitCode))"
    return $path
}

function Test-Unresolved([string]$Text) {
    return $Text -match 'Failed to resolve|Could not resolve host|could not resolve|Name or service not known|Temporary failure in name resolution|not known'
}

function Get-Observation([string]$Text) {
    if ($Text -match 'patient-record-001') { return "sensitive data returned" }
    $ports = @(
        ($Text -split "`n") |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match '^\d+/tcp\s+' }
    )
    if ($ports.Count -gt 0) { return ($ports -join "; ") }
    if ($Text -match 'CONNECTED' -and $Text -match 'self-signed certificate') { return "TLS handshake completed, self-signed certificate" }
    if ($Text -match 'CONNECTED' -and $Text -match 'wrong version number|unexpected eof|no peer certificate') { return "TCP connected, peer is not TLS" }
    if ($Text -match 'Verify return code: 0 \(ok\)') { return "TLS handshake completed" }
    if ($Text -match 'CONNECTED') { return "TCP connected, TLS handshake did not complete" }
    if (Test-Unresolved $Text) { return "name not visible from this network" }
    if ($Text -match 'Connection timed out|Operation timed out|Timeout was reached|timed out|Connection timeout') { return "timed out" }
    if ($Text -match 'No route to host|Network is unreachable') { return "no route" }
    if ($Text -match 'Connection refused') { return "connection refused" }
    if ($Text -match 'SKIPPED:') { return "skipped" }
    $flat = ($Text -replace '\s+', ' ').Trim()
    if ($flat.Length -gt 180) { $flat = $flat.Substring(0, 180) }
    if (-not $flat) { return "empty output" }
    return $flat
}

function Test-ServiceRunning([string]$Service) {
    $result = Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "ps", "-q", $Service)
    return ($result.ExitCode -eq 0 -and $result.Text.Trim().Length -gt 0)
}

function Get-ServiceIps([string]$Service) {
    $idResult = Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "ps", "-q", $Service)
    $id = ($idResult.Text -split '\s+') | Where-Object { $_ } | Select-Object -First 1
    if (-not $id) { return @() }
    $raw = Invoke-Docker @("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", $id)
    $ips = @(($raw.Text -split '\s+') | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    # A bare return unwraps a one-element array into a string, and indexing that string returns a character.
    Write-Output -NoEnumerate $ips
}

function Add-Check {
    param(
        $Checks,
        [string]$Name,
        [string]$CommandLabel,
        $Result
    )
    $Checks.Add([pscustomobject]@{
        Name        = $Name
        Command     = $CommandLabel
        ExitCode    = $Result.ExitCode
        Observation = (Get-Observation $Result.Text)
    }) | Out-Null
}

if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    # exit inside a nested script would kill this session, so each phase is its own process.
    $beforeCode = 0
    $afterCode = 0
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ComposeFile (Join-Path $PSScriptRoot "docker-compose.before.yml") `
        -ProjectName "lab5-seg-before" `
        -OutputDir (Join-Path $PSScriptRoot "..\evidencias\antes") `
        -Phase "before"
    if ($LASTEXITCODE -ne 0) { $beforeCode = $LASTEXITCODE }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ComposeFile (Join-Path $PSScriptRoot "docker-compose.after.yml") `
        -ProjectName "lab5-seg-after" `
        -OutputDir (Join-Path $PSScriptRoot "..\evidencias\despues") `
        -Phase "after"
    if ($LASTEXITCODE -ne 0) { $afterCode = $LASTEXITCODE }
    if ($beforeCode -ne 0 -or $afterCode -ne 0) { exit 1 }
    exit 0
}

Assert-HostToken $GatewayHost "GatewayHost"
Assert-HostToken $BackendHost "BackendHost"
Assert-HostToken $DbHost "DbHost"
Assert-HostToken $AttackerService "AttackerService"
Assert-HostToken $GatewayService "GatewayService"
Assert-HostToken $BackendService "BackendService"
Assert-HostToken $FrontendService "FrontendService"
Assert-HostToken $DbService "DbService"
if ($Phase -notmatch '^[A-Za-z0-9._-]+$') { throw "Phase no valida: $Phase" }

if (-not [System.IO.Path]::IsPathRooted($ComposeFile)) {
    $ComposeFile = Join-Path (Get-Location) $ComposeFile
}
$ComposeFile = [System.IO.Path]::GetFullPath($ComposeFile)
if (-not (Test-Path $ComposeFile)) { throw "No existe el compose: $ComposeFile" }

if ([string]::IsNullOrWhiteSpace($ProjectName)) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($ComposeFile).ToLower() -replace '[^a-z0-9]', ''
    $ProjectName = "lab5$base"
}
if ($ProjectName -notmatch '^[a-z0-9][a-z0-9_-]*$') { throw "ProjectName no valido: $ProjectName" }

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $PSScriptRoot "..\evidencias\custom"
}
if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) $OutputDir
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Get-ChildItem -Path $OutputDir -Filter *.txt -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "phase=$Phase project=$ProjectName"
Write-Host "compose=$ComposeFile"
Write-Host "output=$OutputDir"

$version = Invoke-Docker @("version", "--format", "{{.Server.Version}}")
$composeVersion = Invoke-Docker @("compose", "version")
$envText = @"
phase: $Phase
compose: $ComposeFile
project: $ProjectName
docker_server: $($version.Text.Trim())
compose: $($composeVersion.Text.Trim())
gateway: ${GatewayHost}:${GatewayPort}
backend: ${BackendHost}:${BackendPort}
db: ${DbHost}:${DbPort}
"@
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText((Join-Path $OutputDir "environment.txt"), $envText + "`r`n", $utf8)
if ($version.ExitCode -ne 0) {
    $script:HarnessFailed = $true
    Write-Host $version.Text
    throw "Docker no respondio. Revisa que Docker Desktop este en ejecucion."
}

try {
    try {
    if (-not $SkipUp) {
        Write-Host "deteniendo un stack previo del mismo proyecto, si existe"
        Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "down", "--remove-orphans") | Out-Null
        Write-Host "levantando $Phase"
        $up = Invoke-Docker @(
            "compose", "-f", $ComposeFile, "-p", $ProjectName,
            "up", "-d", "--build", "--wait", "--wait-timeout", "240"
        )
        Save-Result -FileName "compose-up.txt" -CommandLabel "docker compose -f $ComposeFile -p $ProjectName up -d --build --wait --wait-timeout 240" -Result $up
        if ($up.ExitCode -ne 0) {
            $script:HarnessFailed = $true
            $logs = Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "logs", "--no-color")
            Save-Result -FileName "compose-logs.txt" -CommandLabel "docker compose logs --no-color" -Result $logs
            throw "docker compose up fallo (exit $($up.ExitCode)). Revisa compose-up.txt y compose-logs.txt."
        }
    }

    if (-not (Test-ServiceRunning $AttackerService)) {
        $script:HarnessFailed = $true
        throw "No esta corriendo el servicio '$AttackerService'. Agregalo a la red externa con curl, nmap y openssl."
    }

    $readyBody = @"
i=0
while [ "`$i" -lt 40 ]; do
  if curl -k -sS -o /dev/null --connect-timeout 3 --max-time 5 "https://${GatewayHost}:${GatewayPort}/"; then
    exit 0
  fi
  i=`$((i + 1))
  sleep 3
done
echo "gateway did not become ready" >&2
exit 1
"@
    $ready = Invoke-ServiceScript -Service $AttackerService -ScriptBody $readyBody
    Save-Result -FileName "wait-gateway.txt" -CommandLabel "curl -k -sS -o /dev/null --connect-timeout 3 --max-time 5 https://${GatewayHost}:${GatewayPort}/ (retry until ready)" -Result $ready
    if ($ready.ExitCode -ne 0) {
        $script:HarnessFailed = $true
        $logs = Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "logs", "--no-color")
        Save-Result -FileName "compose-logs.txt" -CommandLabel "docker compose logs --no-color" -Result $logs
        throw "El gateway no respondio a tiempo desde el atacante."
    }

    $ps = Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "ps")
    Save-Result -FileName "compose-ps.txt" -CommandLabel "docker compose -p $ProjectName ps" -Result $ps

    $checks = New-Object System.Collections.Generic.List[object]
    $ports = "$GatewayPort,$BackendPort,$DbPort"
    $nmapFlags = "-4 -sT -Pn -p $ports --max-retries 1 --host-timeout 12s"

    foreach ($target in @(
            @{ Name = "gateway"; Host = $GatewayHost },
            @{ Name = "backend"; Host = $BackendHost },
            @{ Name = "db"; Host = $DbHost }
        )) {
        $nmapCmd = "nmap $nmapFlags $($target.Host)"
        $nmap = Invoke-ServiceScript -Service $AttackerService -ScriptBody $nmapCmd
        Save-Result -FileName "nmap-$($target.Name).txt" -CommandLabel $nmapCmd -Result $nmap
        Add-Check $checks "attacker nmap $($target.Name)" $nmapCmd $nmap

        if (Test-Unresolved $nmap.Text) {
            $ips = Get-ServiceIps $(if ($target.Name -eq "gateway") { $GatewayService } elseif ($target.Name -eq "backend") { $BackendService } else { $DbService })
            if ($ips.Count -eq 0) {
                $miss = [pscustomobject]@{ Text = "SKIPPED: no se pudo obtener la IP de $($target.Host)"; ExitCode = 0 }
                Save-Result -FileName "nmap-$($target.Name)-by-ip.txt" -CommandLabel "nmap $nmapFlags <ip>" -Result $miss
            } else {
                $chunks = @()
                $codes = @()
                foreach ($ip in $ips) {
                    $ipCmd = "nmap $nmapFlags $ip"
                    $ipRun = Invoke-ServiceScript -Service $AttackerService -ScriptBody $ipCmd
                    $chunks += "COMMAND: $ipCmd`n$($ipRun.Text)"
                    $codes += $ipRun.ExitCode
                }
                $joined = [pscustomobject]@{ Text = ($chunks -join "`n"); ExitCode = ($codes | Select-Object -Last 1) }
                $label = "nmap $nmapFlags " + ($ips -join ",")
                Save-Result -FileName "nmap-$($target.Name)-by-ip.txt" -CommandLabel $label -Result $joined
                Add-Check $checks "attacker nmap $($target.Name) by ip" $label $joined
            }
        }
    }

    $curlGatewayCmd = "curl -k -sS -D - --connect-timeout 5 --max-time 10 https://${GatewayHost}:${GatewayPort}/"
    $curlGateway = Invoke-ServiceScript -Service $AttackerService -ScriptBody $curlGatewayCmd
    Save-Result -FileName "curl-gateway.txt" -CommandLabel $curlGatewayCmd -Result $curlGateway
    Add-Check $checks "attacker curl gateway" $curlGatewayCmd $curlGateway
    if ($Phase -in @("before", "after") -and $curlGateway.Text -notmatch "patient-record-001") {
        $script:HarnessFailed = $true
    }

    $curlBackendCmd = "curl -sS -D - --connect-timeout 5 --max-time 8 http://${BackendHost}:${BackendPort}/"
    $curlBackend = Invoke-ServiceScript -Service $AttackerService -ScriptBody $curlBackendCmd
    Save-Result -FileName "curl-backend.txt" -CommandLabel $curlBackendCmd -Result $curlBackend
    Add-Check $checks "attacker curl backend" $curlBackendCmd $curlBackend
    if (Test-Unresolved $curlBackend.Text) {
        $ips = Get-ServiceIps $BackendService
        if ($ips.Count -gt 0) {
            $ip = $ips[0]
            $ipCmd = "curl -sS -D - --connect-timeout 5 --max-time 8 http://${ip}:${BackendPort}/"
            $ipRun = Invoke-ServiceScript -Service $AttackerService -ScriptBody $ipCmd
            Save-Result -FileName "curl-backend-by-ip.txt" -CommandLabel $ipCmd -Result $ipRun
            Add-Check $checks "attacker curl backend by ip" $ipCmd $ipRun
        }
    }

    foreach ($target in @(
            @{ Name = "gateway"; Host = $GatewayHost; Port = $GatewayPort },
            @{ Name = "backend"; Host = $BackendHost; Port = $BackendPort },
            @{ Name = "db"; Host = $DbHost; Port = $DbPort }
        )) {
        $sslCmd = "timeout 8 openssl s_client -connect $($target.Host):$($target.Port) -servername $($target.Host) </dev/null"
        $ssl = Invoke-ServiceScript -Service $AttackerService -ScriptBody $sslCmd
        Save-Result -FileName "openssl-$($target.Name).txt" -CommandLabel $sslCmd -Result $ssl
        Add-Check $checks "attacker openssl $($target.Name)" $sslCmd $ssl
        if (Test-Unresolved $ssl.Text) {
            $service = $(if ($target.Name -eq "gateway") { $GatewayService } elseif ($target.Name -eq "backend") { $BackendService } else { $DbService })
            $ips = Get-ServiceIps $service
            if ($ips.Count -gt 0) {
                $ip = $ips[0]
                $ipCmd = "timeout 8 openssl s_client -connect ${ip}:$($target.Port) </dev/null"
                $ipRun = Invoke-ServiceScript -Service $AttackerService -ScriptBody $ipCmd
                Save-Result -FileName "openssl-$($target.Name)-by-ip.txt" -CommandLabel $ipCmd -Result $ipRun
                Add-Check $checks "attacker openssl $($target.Name) by ip" $ipCmd $ipRun
            }
        }
    }

    $internal = @(
        @{
            File = "internal-gateway-to-backend.txt"
            Service = $GatewayService
            Command = "curl -sS -D - --connect-timeout 5 --max-time 8 http://${BackendHost}:${BackendPort}/"
        },
        @{
            File = "internal-backend-to-db.txt"
            Service = $BackendService
            Command = "timeout 8 openssl s_client -connect ${DbHost}:${DbPort} </dev/null"
        },
        @{
            File = "internal-frontend-to-backend.txt"
            Service = $FrontendService
            Command = "curl -sS -D - --connect-timeout 5 --max-time 8 http://${BackendHost}:${BackendPort}/"
        },
        @{
            File = "internal-frontend-to-db.txt"
            Service = $FrontendService
            Command = "timeout 8 openssl s_client -connect ${DbHost}:${DbPort} </dev/null"
        },
        @{
            File = "internal-gateway-to-db.txt"
            Service = $GatewayService
            Command = "timeout 8 openssl s_client -connect ${DbHost}:${DbPort} </dev/null"
        }
    )

    foreach ($item in $internal) {
        if (-not (Test-ServiceRunning $item.Service)) {
            $skipped = [pscustomobject]@{
                Text = "SKIPPED: el servicio $($item.Service) no esta corriendo en este compose."
                ExitCode = 0
            }
            Save-Result -FileName $item.File -CommandLabel $item.Command -Result $skipped
            Add-Check $checks $item.File $item.Command $skipped
            continue
        }
        $run = Invoke-ServiceScript -Service $item.Service -ScriptBody $item.Command
        Save-Result -FileName $item.File -CommandLabel $item.Command -Result $run
        Add-Check $checks $item.File $item.Command $run
    }

    $summary = New-Object System.Text.StringBuilder
    [void]$summary.AppendLine("phase: $Phase")
    [void]$summary.AppendLine("compose: $ComposeFile")
    [void]$summary.AppendLine("project: $ProjectName")
    [void]$summary.AppendLine("note: raw command output is in the sibling txt files. This summary only classifies it.")
    if ($Phase -eq "after") {
        [void]$summary.AppendLine("limitation: internal-gateway-to-db stays open in this harness. The team ACL (Fabian) should turn that check into a timeout. See section 7 of I5_2c.md.")
    }
    [void]$summary.AppendLine("")
    foreach ($check in $checks) {
        [void]$summary.AppendLine("BEGIN $($check.Name)")
        [void]$summary.AppendLine("command: $($check.Command)")
        [void]$summary.AppendLine("exit: $($check.ExitCode)")
        [void]$summary.AppendLine("observation: $($check.Observation)")
        [void]$summary.AppendLine("END")
        [void]$summary.AppendLine("")
    }
    [System.IO.File]::WriteAllText((Join-Path $OutputDir "summary.txt"), $summary.ToString(), $utf8)
    Write-Host "summary written"
    } catch {
        $script:HarnessFailed = $true
        Write-Host "ERROR: $($_.Exception.Message)"
    }
}
finally {
    if (-not $SkipDown) {
        Write-Host "apagando $ProjectName"
        Invoke-Docker @("compose", "-f", $ComposeFile, "-p", $ProjectName, "down", "--remove-orphans") | Out-Null
    }
}

if ($script:HarnessFailed) { exit 1 }
exit 0
