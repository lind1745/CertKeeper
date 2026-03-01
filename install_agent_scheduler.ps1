# install_agent_scheduler.ps1
# Скрипт для установки агента мониторинга сертификатов в планировщик Windows
# Запускать от имени администратора!

param(
    [string]$ServerUrl = "http://192.168.1.100:5000/api/report",  # IP вашего сервера
    [string]$AgentSourcePath = "\\SERVER\share\send_cert_report.ps1",  # Путь к исходному файлу агента
    [string]$InstallPath = "C:\UTM_Cert_Check",  # Папка установки
    [string]$TaskName = "UTM Certificate Monitor",  # Имя задачи в планировщике
    [switch]$SkipOpenSC,  # Пропустить проверку OpenSC
    [switch]$SkipRutoken  # Пропустить проверку драйвера Рутокен
)

# Проверка прав администратора
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Ошибка: Скрипт должен быть запущен от имени администратора!" -ForegroundColor Red
    Write-Host "Запустите PowerShell от имени администратора и попробуйте снова." -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "="*60 -ForegroundColor Green
Write-Host "     УСТАНОВКА АГЕНТА МОНИТОРИНГА СЕРТИФИКАТОВ" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Green
Write-Host "Компьютер: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Сервер: $ServerUrl" -ForegroundColor Cyan
Write-Host "Папка установки: $InstallPath" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Green
Write-Host ""

# Функция логирования
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

# ========== 1. Проверка наличия OpenSC ==========
if (-not $SkipOpenSC) {
    Write-Log "Проверка наличия OpenSC..." -Color Yellow
    $toolPath = "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
    
    if (-not (Test-Path $toolPath)) {
        Write-Log "❌ OpenSC не найден!" -Color Red
        Write-Log "Скачайте OpenSC с сайта: https://github.com/OpenSC/OpenSC/releases" -Color Yellow
        Write-Log "Установите OpenSC и запустите скрипт снова." -Color Yellow
        
        $choice = Read-Host "Хотите пропустить проверку OpenSC и продолжить? (y/n)"
        if ($choice -ne 'y') {
            exit 1
        }
    } else {
        Write-Log "✅ OpenSC найден" -Color Green
    }
}

# ========== 2. Проверка наличия драйвера Рутокен ==========
if (-not $SkipRutoken) {
    Write-Log "Проверка наличия драйвера Рутокен..." -Color Yellow
    $modulePath = "C:\Windows\System32\rtpkcs11ecp.dll"
    
    if (-not (Test-Path $modulePath)) {
        Write-Log "❌ Драйвер Рутокен не найден!" -Color Red
        Write-Log "Скачайте драйвер с сайта: https://www.rutoken.ru/support/download/drivers/" -Color Yellow
        Write-Log "Установите драйвер и запустите скрипт снова." -Color Yellow
        
        $choice = Read-Host "Хотите пропустить проверку драйвера и продолжить? (y/n)"
        if ($choice -ne 'y') {
            exit 1
        }
    } else {
        Write-Log "✅ Драйвер Рутокен найден" -Color Green
    }
}

# ========== 3. Создание папки для скрипта ==========
Write-Log "Создание папки $InstallPath..." -Color Yellow
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Log "✅ Папка создана" -Color Green
} else {
    Write-Log "✅ Папка уже существует" -Color Green
}

# ========== 4. Копирование скрипта ==========
$agentScriptPath = "$InstallPath\send_cert_report.ps1"

# Если указан источник, копируем оттуда
if ($AgentSourcePath -ne "\\SERVER\share\send_cert_report.ps1") {
    Write-Log "Копирование агента из $AgentSourcePath..." -Color Yellow
    try {
        Copy-Item -Path $AgentSourcePath -Destination $agentScriptPath -Force
        Write-Log "✅ Агент скопирован" -Color Green
    }
    catch {
        Write-Log "❌ Ошибка копирования: $_" -Color Red
        
        # Если не удалось скопировать, просим указать путь
        $manualPath = Read-Host "Укажите полный путь к файлу send_cert_report.ps1"
        if (Test-Path $manualPath) {
            Copy-Item -Path $manualPath -Destination $agentScriptPath -Force
            Write-Log "✅ Агент скопирован" -Color Green
        } else {
            Write-Log "❌ Файл не найден. Установка прервана." -Color Red
            exit 1
        }
    }
} else {
    # Если источник не указан, проверяем наличие скрипта в текущей папке
    $localScript = Join-Path $PSScriptRoot "send_cert_report.ps1"
    if (Test-Path $localScript) {
        Write-Log "Копирование агента из локальной папки..." -Color Yellow
        Copy-Item -Path $localScript -Destination $agentScriptPath -Force
        Write-Log "✅ Агент скопирован" -Color Green
    } else {
        Write-Log "⚠️ Файл агента не найден. Будет создан базовый шаблон." -Color Yellow
        
        # Создаем базовый шаблон скрипта
        $templateScript = @"
# send_cert_report.ps1
param(
    [string]`$ServerUrl = "$ServerUrl",
    [string]`$LogFile = "C:\UTM_Cert_Check\send_report.log"
)

`$toolPath = "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
`$modulePath = "C:\Windows\System32\rtpkcs11ecp.dll"

Write-Host "Проверка сертификатов на `$env:COMPUTERNAME"
Write-Host "Сервер: `$ServerUrl"

# Здесь должна быть логика проверки сертификатов
# Скопируйте полную версию скрипта с сервера

# Простой тестовый отчет
`$report = @{
    computer_name = `$env:COMPUTERNAME
    timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    opensc_installed = Test-Path `$toolPath
    rutoken_driver = Test-Path `$modulePath
    utm_certificates = @()
    fns_certificates = @()
}

try {
    `$jsonBody = `$report | ConvertTo-Json
    Invoke-RestMethod -Uri `$ServerUrl -Method Post -Body `$jsonBody -ContentType "application/json"
    Write-Host "Отчет отправлен"
}
catch {
    Write-Host "Ошибка: `$_"
}
"@
        $templateScript | Out-File -FilePath $agentScriptPath -Encoding UTF8
        Write-Log "✅ Базовый шаблон создан" -Color Green
        Write-Log "⚠️ Замените его на полную версию скрипта с сервера!" -Color Yellow
    }
}

# ========== 5. Настройка ServerUrl в скрипте ==========
Write-Log "Настройка адреса сервера в скрипте..." -Color Yellow
try {
    $scriptContent = Get-Content -Path $agentScriptPath -Raw -Encoding UTF8
    $scriptContent = $scriptContent -replace '(?<=param\(\s*\[string\]\$ServerUrl = ")[^"]*', $ServerUrl
    $scriptContent | Out-File -FilePath $agentScriptPath -Encoding UTF8 -Force
    Write-Log "✅ Адрес сервера установлен: $ServerUrl" -Color Green
}
catch {
    Write-Log "⚠️ Не удалось автоматически настроить адрес сервера" -Color Yellow
}

# ========== 6. Создание задачи в планировщике ==========
Write-Log "Создание задачи в планировщике Windows..." -Color Yellow

# Проверяем, существует ли уже задача
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Log "⚠️ Задача '$TaskName' уже существует" -Color Yellow
    $choice = Read-Host "Перезаписать существующую задачу? (y/n)"
    if ($choice -eq 'y') {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "✅ Старая задача удалена" -Color Green
    } else {
        Write-Log "Установка пропущена пользователем" -Color Yellow
        exit 0
    }
}

# Действие - запуск PowerShell скрипта
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentScriptPath`""

# Триггеры - по умолчанию запускаем 3 раза в день
$triggerMorning = New-ScheduledTaskTrigger -Daily -At 09:00AM
$triggerAfternoon = New-ScheduledTaskTrigger -Daily -At 02:00PM
$triggerEvening = New-ScheduledTaskTrigger -Daily -At 07:00PM
$triggers = @($triggerMorning, $triggerAfternoon, $triggerEvening)

# Настройки задачи
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -Compatibility Win8 `
    -RestartInterval (New-TimeSpan -Minutes 15) `
    -RestartCount 3

# Пользователь - SYSTEM (максимальные права)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Регистрируем задание
try {
    Register-ScheduledTask -TaskName $TaskName `
        -Action $action `
        -Trigger $triggers `
        -Settings $settings `
        -Principal $principal `
        -Description "Проверка срока действия сертификатов УТМ и ФНС" `
        -Force

    Write-Log "✅ Задача в планировщике создана успешно" -Color Green
}
catch {
    Write-Log "❌ Ошибка при создании задачи: $_" -Color Red
    exit 1
}

# ========== 7. Тестовый запуск ==========
Write-Log "" -Color White
Write-Log "="*60 -Color Green
Write-Log "УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!" -Color Green
Write-Log "="*60 -Color Green
Write-Log "Задача: $TaskName" -Color Cyan
Write-Log "Расписание: 09:00, 14:00, 19:00 ежедневно" -Color Cyan
Write-Log "Скрипт: $agentScriptPath" -Color Cyan
Write-Log "Сервер: $ServerUrl" -Color Cyan
Write-Log "="*60 -Color Green
Write-Log ""

$runTest = Read-Host "Выполнить тестовый запуск сейчас? (y/n)"
if ($runTest -eq 'y') {
    Write-Log "Запуск тестовой проверки..." -Color Yellow
    try {
        & $agentScriptPath
        Write-Log "✅ Тестовый запуск выполнен" -Color Green
    }
    catch {
        Write-Log "❌ Ошибка при тестовом запуске: $_" -Color Red
    }
}

Write-Log "Установка завершена!" -Color Green
pause