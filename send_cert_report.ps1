# send_cert_report.ps1 - Расширенная версия с поиском ФНС на токенах
param(
    [string]$ServerUrl = "http://127.0.0.1:5000/api/report",
    [string]$LogFile = "C:\UTM_Cert_Check\send_report.log"
)

# Создаем папку для логов
$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Функция логирования
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host "$timestamp - $Message"
}

# Функция дедупликации сертификатов
function Deduplicate-Certificates {
    param(
        [array]$Certificates,
        [string]$SourceName
    )
    
    if ($Certificates.Count -le 1) {
        return $Certificates
    }
    
    Write-Log "Дедупликация $SourceName сертификатов: было $($Certificates.Count)"
    
    $grouped = @{}
    
    foreach ($cert in $Certificates) {
        $key = ""
        
        if ($cert.inn -and $cert.inn -ne "") {
            $key = "INN:$($cert.inn)"
        }
        elseif ($cert.organization -and $cert.organization -ne "") {
            $key = "ORG:$($cert.organization)"
        }
        elseif ($cert.full_name -and $cert.full_name -ne "") {
            $key = "NAME:$($cert.full_name)"
        }
        elseif ($cert.subject -and $cert.subject -ne "") {
            $key = "SUBJ:$($cert.subject.Substring(0, [Math]::Min(50, $cert.subject.Length)))"
        }
        else {
            $key = "UNIQUE:$([Guid]::NewGuid().ToString())"
        }
        
        if (-not $grouped.ContainsKey($key)) {
            $grouped[$key] = @()
        }
        $grouped[$key] += $cert
    }
    
    $deduplicated = @()
    $removedCount = 0
    
    foreach ($key in $grouped.Keys) {
        $group = $grouped[$key]
        
        if ($group.Count -eq 1) {
            $deduplicated += $group[0]
        }
        else {
            $sorted = $group | Sort-Object -Property @{Expression={[datetime]::ParseExact($_.expiry_date, 'dd.MM.yyyy HH:mm', $null)}} -Descending
            $best = $sorted[0]
            $deduplicated += $best
            $removedCount += ($group.Count - 1)
            
            Write-Log "  Для ключа '$key' найдено $($group.Count) сертификатов:"
            foreach ($c in $sorted) {
                $keep = if ($c -eq $best) { "✅ ОСТАВЛЯЕМ" } else { "❌ УДАЛЯЕМ" }
                $name = if ($c.full_name) { $c.full_name } elseif ($c.organization) { $c.organization } else { "Неизвестно" }
                Write-Log "    - $name до $($c.expiry_date) $keep"
            }
        }
    }
    
    Write-Log "  После дедупликации: осталось $($deduplicated.Count), удалено дублей: $removedCount"
    return $deduplicated
}

# Функция для извлечения информации из сертификата
function Extract-CertInfo {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$Source,
        [string]$SlotInfo = ""
    )
    
    $daysLeft = ($Cert.NotAfter - (Get-Date)).Days
    
    # Извлекаем ИНН
    $inn = ""
    if ($Cert.Subject -match "ИНН[= ]([0-9]{10,12})") {
        $inn = $matches[1]
    }
    
    # Извлекаем организацию
    $organization = ""
    if ($Cert.Subject -match "O=([^,]+)") {
        $organization = $matches[1].Trim()
    }
    elseif ($Cert.Subject -match "CN=([^,]+)") {
        $organization = $matches[1].Trim()
    }
    
    # Извлекаем фамилию
    $lastName = ""
    if ($Cert.Subject -match "SN=([^,]+)") {
        $lastName = $matches[1].Trim()
    }
    
    # Извлекаем имя и отчество
    $firstName = ""
    $middleName = ""
    if ($Cert.Subject -match "G=([^,]+)") {
        $fullNamePart = $matches[1].Trim()
        $nameParts = $fullNamePart -split ' '
        if ($nameParts.Count -ge 1) { $firstName = $nameParts[0] }
        if ($nameParts.Count -ge 2) { $middleName = $nameParts[1] }
    }
    
    # Формируем полное имя
    $fullName = ""
    if ($lastName -or $firstName -or $middleName) {
        $fullName = "$lastName $firstName $middleName".Trim()
        if ($fullName -eq "") { $fullName = $null }
    }
    
    if (-not $fullName) {
        if ($Cert.Subject -match "CN=([^,]+)") {
            $fullName = $matches[1].Trim()
        }
    }
    
    # Проверяем, похож ли на ФНС
    $isFNS = ($Cert.Subject -like "*ФНС*" -or 
              $Cert.Subject -like "*FNS*" -or 
              $Cert.Subject -like "*налог*" -or
              $Cert.Issuer -like "*ФНС*" -or
              $Cert.Issuer -like "*FNS*" -or
              $Cert.Subject -like "*ИНН*")
    
    return @{
        thumbprint = $Cert.Thumbprint
        subject = $Cert.Subject
        last_name = $lastName
        first_name = $firstName
        middle_name = $middleName
        full_name = $fullName
        organization = $organization
        inn = $inn
        issuer = $Cert.Issuer
        expiry_date = $Cert.NotAfter.ToString("dd.MM.yyyy HH:mm")
        days_left = $daysLeft
        status = if ($daysLeft -lt 0) { "Expired" } 
                 elseif ($daysLeft -lt 30) { "Warning" } 
                 else { "Valid" }
        source = $source
        is_fns = $isFNS
        slot_info = $SlotInfo
        store = if ($Source -eq "registry" -and $Cert.PSPath -like "*CurrentUser*") { "CurrentUser" } else { "LocalMachine" }
    }
}

Write-Log "="*50
Write-Log "Запуск проверки сертификатов (УТМ + ФНС на токенах и в реестре)"

# Проверяем наличие компонентов для УТМ
$toolPath = "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
$modulePath = "C:\Windows\System32\rtpkcs11ecp.dll"

$report = @{
    computer_name = $env:COMPUTERNAME
    timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    opensc_installed = Test-Path $toolPath
    rutoken_driver = Test-Path $modulePath
    utm_certificates = @()
    fns_certificates_raw = @()
    fns_certificates = @()
    fns_token_certificates = @()
    deduplication_stats = @{
        fns_original_count = 0
        fns_final_count = 0
    }
}

Write-Log "Компьютер: $($report.computer_name)"
Write-Log "OpenSC установлен: $($report.opensc_installed)"
Write-Log "Драйвер Рутокен: $($report.rutoken_driver)"

# ========== 1. Проверка УТМ сертификатов на токене ==========
if ($report.opensc_installed -and $report.rutoken_driver) {
    Write-Log "Проверка сертификатов УТМ на токене..."
    
    try {
        # Сначала получаем список слотов, чтобы найти токен с УТМ
        $slotsOutput = & $toolPath --module $modulePath --list-slots 2>&1
        
        $slots = @()
        $currentSlot = $null
        
        foreach ($line in $slotsOutput) {
            if ($line -match "Slot (\d+) \(0x[0-9a-f]+\): (.*)") {
                if ($currentSlot) { $slots += $currentSlot }
                $currentSlot = @{
                    id = $matches[1]
                    description = $matches[2].Trim()
                    has_token = ($line -notlike "*(empty)*")
                }
            }
            elseif ($currentSlot -and $line -match "token label\s*:\s*(.*)") {
                $currentSlot.token_label = $matches[1].Trim()
            }
            elseif ($currentSlot -and $line -match "serial num\s*:\s*(.*)") {
                $currentSlot.serial = $matches[1].Trim()
            }
        }
        if ($currentSlot) { $slots += $currentSlot }
        
        # Проверяем каждый слот с токеном на наличие сертификатов
        $tempDir = "$env:TEMP\cert_check_$(Get-Random)"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        foreach ($slot in $slots | Where-Object { $_.has_token }) {
            $certsOutput = & $toolPath --module $modulePath --slot $slot.id --list-objects --type cert 2>&1
            
            $certIds = @()
            foreach ($line in $certsOutput) {
                if ($line -match "ID:\s*([a-f0-9]+)") {
                    $certIds += $matches[1]
                }
            }
            
            if ($certIds.Count -gt 0) {
                Write-Log "  Слот $($slot.id): найдено сертификатов: $($certIds.Count)"
                
                foreach ($certId in $certIds) {
                    $certFile = "$tempDir\cert_$certId.der"
                    
                    & $toolPath --module $modulePath --slot $slot.id --read-object --type cert --id $certId --output-file $certFile 2>$null
                    
                    if (Test-Path $certFile) {
                        $certutilOutput = certutil -dump $certFile 2>&1 | Out-String
                        $expiryLine = $certutilOutput | Select-String -Pattern "NotAfter"
                        
                        if ($expiryLine -match "NotAfter:\s*(.*)") {
                            $expiryDateStr = $matches[1].Trim()
                            
                            try {
                                $expiryDate = [datetime]::ParseExact($expiryDateStr, 'dd.MM.yyyy HH:mm', $null)
                                $today = Get-Date
                                $daysLeft = ($expiryDate - $today).Days
                                
                                $certInfo = @{
                                    id = $certId
                                    expiry_date = $expiryDateStr
                                    days_left = $daysLeft
                                    status = if ($daysLeft -lt 0) { "Expired" } 
                                             elseif ($daysLeft -lt 30) { "Warning" } 
                                             else { "Valid" }
                                    source = "utm_token"
                                    slot = $slot.id
                                    token_label = $slot.token_label
                                }
                                $report.utm_certificates += $certInfo
                                Write-Log "    УТМ сертификат: истекает $expiryDateStr, осталось $daysLeft дн."
                            }
                            catch {
                                Write-Log "    Ошибка парсинга даты: $_"
                            }
                        }
                        Remove-Item $certFile -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Всего найдено УТМ сертификатов: $($report.utm_certificates.Count)"
    }
    catch {
        $report.error_utm = $_.ToString()
        Write-Log "Ошибка при проверке УТМ сертификатов: $_"
    }
}

# ========== 2. Проверка ФНС сертификатов в реестре Windows ==========
Write-Log "Проверка сертификатов ФНС в хранилищах Windows..."

try {
    $userCerts = @(Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue)
    $machineCerts = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue)
    
    $allCerts = $userCerts + $machineCerts
    
    Write-Log "Найдено сертификатов в реестре: $($allCerts.Count)"
    
    foreach ($cert in $allCerts) {
        if ($cert -and $cert -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $certInfo = Extract-CertInfo -Cert $cert -Source "registry"
            if ($certInfo.is_fns) {
                $report.fns_certificates_raw += $certInfo
                Write-Log "  Найден ФНС сертификат в реестре: $($certInfo.full_name), ИНН: $($certInfo.inn), истекает: $($certInfo.expiry_date)"
            }
        }
    }
}
catch {
    $report.error_fns_registry = $_.ToString()
    Write-Log "Ошибка при проверке ФНС сертификатов в реестре: $_"
}

# ========== 3. Проверка ФНС сертификатов на ВСЕХ токенах ==========
if ($report.opensc_installed -and $report.rutoken_driver) {
    Write-Log "Проверка ФНС сертификатов на всех доступных токенах..."
    
    try {
        $slotsOutput = & $toolPath --module $modulePath --list-slots 2>&1
        
        $slots = @()
        $currentSlot = $null
        
        foreach ($line in $slotsOutput) {
            if ($line -match "Slot (\d+) \(0x[0-9a-f]+\): (.*)") {
                if ($currentSlot) { $slots += $currentSlot }
                $currentSlot = @{
                    id = $matches[1]
                    description = $matches[2].Trim()
                    has_token = ($line -notlike "*(empty)*")
                }
            }
            elseif ($currentSlot -and $line -match "token label\s*:\s*(.*)") {
                $currentSlot.token_label = $matches[1].Trim()
            }
            elseif ($currentSlot -and $line -match "serial num\s*:\s*(.*)") {
                $currentSlot.serial = $matches[1].Trim()
            }
        }
        if ($currentSlot) { $slots += $currentSlot }
        
        $slotsWithTokens = $slots | Where-Object { $_.has_token }
        Write-Log "Найдено слотов: $($slots.Count), с токенами: $($slotsWithTokens.Count)"
        
        $tempDir = "$env:TEMP\cert_check_fns_$(Get-Random)"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        foreach ($slot in $slotsWithTokens) {
            Write-Log "Проверка слота $($slot.id): $($slot.description), метка: $($slot.token_label)"
            
            $certsOutput = & $toolPath --module $modulePath --slot $slot.id --list-objects --type cert 2>&1
            
            $certIds = @()
            foreach ($line in $certsOutput) {
                if ($line -match "ID:\s*([a-f0-9]+)") {
                    $certIds += $matches[1]
                }
            }
            
            Write-Log "  Найдено сертификатов: $($certIds.Count)"
            
            foreach ($certId in $certIds) {
                $certFile = "$tempDir\cert_$certId.der"
                
                & $toolPath --module $modulePath --slot $slot.id --read-object --type cert --id $certId --output-file $certFile 2>$null
                
                if (Test-Path $certFile) {
                    try {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $cert.Import($certFile)
                        
                        $slotInfo = "Slot $($slot.id): $($slot.token_label) (sn: $($slot.serial))"
                        $certInfo = Extract-CertInfo -Cert $cert -Source "token" -SlotInfo $slotInfo
                        
                        if ($certInfo.is_fns) {
                            $report.fns_certificates_raw += $certInfo
                            $report.fns_token_certificates += $certInfo
                            Write-Log "  ✅ Найден ФНС сертификат на токене: $($certInfo.full_name), ИНН: $($certInfo.inn)"
                        }
                        
                        $cert.Dispose()
                    }
                    catch {
                        Write-Log "  Ошибка при анализе сертификата: $_"
                    }
                    finally {
                        Remove-Item $certFile -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        $report.error_fns_tokens = $_.ToString()
        Write-Log "Ошибка при проверке ФНС сертификатов на токенах: $_"
    }
}

# ========== 4. Дедупликация ФНС сертификатов ==========
Write-Log "Дедупликация ФНС сертификатов..."
$report.deduplication_stats.fns_original_count = $report.fns_certificates_raw.Count

if ($report.fns_certificates_raw.Count -gt 0) {
    $report.fns_certificates = Deduplicate-Certificates -Certificates $report.fns_certificates_raw -SourceName "ФНС (реестр + токены)"
    $report.deduplication_stats.fns_final_count = $report.fns_certificates.Count
    
    Write-Log "Итог: найдено всего ФНС сертификатов: $($report.fns_certificates_raw.Count)"
    Write-Log "  - В реестре: $(($report.fns_certificates_raw | Where-Object { $_.source -eq 'registry' }).Count)"
    Write-Log "  - На токенах: $(($report.fns_certificates_raw | Where-Object { $_.source -eq 'token' }).Count)"
    Write-Log "После дедупликации осталось: $($report.fns_certificates.Count)"
} else {
    $report.fns_certificates = @()
    $report.deduplication_stats.fns_final_count = 0
    Write-Log "ФНС сертификаты не найдены"
}

# ========== 5. Отправка отчета ==========
try {
    Write-Log "Отправка отчета на сервер $ServerUrl"
    
    $jsonBody = $report | ConvertTo-Json -Depth 5
    
    $tempJsonFile = "$env:TEMP\report_$(Get-Random).json"
    $jsonBody | Out-File -FilePath $tempJsonFile -Encoding UTF8
    
    $jsonContent = Get-Content -Path $tempJsonFile -Raw -Encoding UTF8
    
    $headers = @{
        "Content-Type" = "application/json; charset=utf-8"
        "Accept" = "application/json"
    }
    
    Write-Log "Размер отчета: $($jsonContent.Length) байт"
    
    $response = Invoke-RestMethod -Uri $ServerUrl -Method Post -Body $jsonContent -Headers $headers -ContentType "application/json; charset=utf-8"
    
    Remove-Item $tempJsonFile -Force -ErrorAction SilentlyContinue
    
    if ($response.status -eq "ok") {
        Write-Log "✅ Отчет успешно отправлен"
    } else {
        Write-Log "⚠️ Сервер вернул: $($response | ConvertTo-Json)"
    }
}
catch {
    Write-Log "❌ Ошибка отправки отчета: $_"
    
    $backupFile = "$LogDir\backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $backupFile -Encoding UTF8
    Write-Log "Отчет сохранен локально: $backupFile"
}

Write-Log "Проверка завершена"
Write-Log "="*50