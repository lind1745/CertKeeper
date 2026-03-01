# utm_cert_server.py
from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
from pathlib import Path

app = Flask(__name__)

# Настройки
DATA_DIR = Path("utm_cert_data")
DATA_DIR.mkdir(exist_ok=True)
REPORT_FILE = DATA_DIR / "all_reports.json"
ALERT_DAYS = 30  # За сколько дней предупреждать

def load_reports():
    """Загружает все отчеты из файла"""
    if REPORT_FILE.exists():
        with open(REPORT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_reports(reports):
    """Сохраняет отчеты в файл"""
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        json.dump(reports, f, ensure_ascii=False, indent=2)

@app.route('/api/report', methods=['POST'])
def receive_report():
    """Принимает отчет от клиента"""
    try:
        # Получаем JSON с правильной обработкой UTF-8
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No data"}), 400
        
        computer_name = data.get('computer_name')
        if not computer_name:
            return jsonify({"error": "No computer_name"}), 400
        
        # Добавляем временную метку получения
        data['received_at'] = datetime.now().isoformat()
        
        # Загружаем все отчеты
        reports = load_reports()
        
        # Сохраняем отчет этого компьютера
        reports[computer_name] = data
        
        # Сохраняем также отдельный файл для каждого компьютера
        computer_file = DATA_DIR / f"{computer_name}.json"
        with open(computer_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        save_reports(reports)
        
        print(f"[{datetime.now().strftime('%d.%m.%Y %H:%M:%S')}] Получен отчет от {computer_name}")
        print(f"  УТМ сертификатов: {len(data.get('utm_certificates', []))}")
        
        # Проверяем ФНС сертификаты (может быть список или объект)
        fns_certs = data.get('fns_certificates', [])
        if isinstance(fns_certs, dict):
            print(f"  ФНС сертификатов (объект): 1")
        elif isinstance(fns_certs, list):
            print(f"  ФНС сертификатов (список): {len(fns_certs)}")
        else:
            print(f"  ФНС сертификатов: нет")
        
        # Статистика дедупликации
        dedup_stats = data.get('deduplication_stats', {})
        if dedup_stats:
            print(f"  Дедупликация ФНС: было {dedup_stats.get('fns_original_count', 0)} -> стало {dedup_stats.get('fns_final_count', 0)}")
        
        return jsonify({"status": "ok", "received": computer_name})
    
    except Exception as e:
        print(f"Ошибка: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports', methods=['GET'])
def get_all_reports():
    """Возвращает все отчеты"""
    reports = load_reports()
    return jsonify(reports)

@app.route('/api/report/<computer_name>', methods=['GET'])
def get_computer_report(computer_name):
    """Возвращает отчет конкретного компьютера"""
    reports = load_reports()
    if computer_name in reports:
        return jsonify(reports[computer_name])
    return jsonify({"error": "Not found"}), 404

@app.route('/api/check_alerts', methods=['GET'])
def check_alerts():
    """Проверяет все компьютеры на наличие проблем"""
    reports = load_reports()
    alerts = []
    
    for comp_name, data in reports.items():
        computer_alerts = {
            'computer': comp_name,
            'problems': [],
            'utm_certificates': [],
            'fns_certificates': []
        }
        
        # Проверяем наличие компонентов
        if not data.get('opensc_installed'):
            computer_alerts['problems'].append('OpenSC not installed')
        
        if not data.get('rutoken_driver'):
            computer_alerts['problems'].append('Rutoken driver not installed')
        
        # Проверяем УТМ сертификаты
        utm_certs = data.get('utm_certificates', [])
        if isinstance(utm_certs, list):
            for cert in utm_certs:
                if isinstance(cert, dict):
                    days_left = cert.get('days_left', 999)
                    if days_left < ALERT_DAYS:
                        computer_alerts['utm_certificates'].append({
                            'id': cert.get('id'),
                            'expiry_date': cert.get('expiry_date'),
                            'days_left': days_left,
                            'status': 'expired' if days_left < 0 else 'warning'
                        })
        
        # Проверяем ФНС сертификаты (может быть список или объект)
        fns_data = data.get('fns_certificates', [])
        fns_certs = []
        
        if isinstance(fns_data, dict):
            fns_certs = [fns_data]
        elif isinstance(fns_data, list):
            fns_certs = fns_data
        
        for cert in fns_certs:
            if isinstance(cert, dict):
                days_left = cert.get('days_left', 999)
                if days_left < ALERT_DAYS:
                    computer_alerts['fns_certificates'].append({
                        'full_name': cert.get('full_name', ''),
                        'organization': cert.get('organization', ''),
                        'inn': cert.get('inn', ''),
                        'expiry_date': cert.get('expiry_date'),
                        'days_left': days_left,
                        'status': 'expired' if days_left < 0 else 'warning'
                    })
        
        # Если есть проблемы, добавляем в общий список
        if (computer_alerts['problems'] or 
            computer_alerts['utm_certificates'] or 
            computer_alerts['fns_certificates']):
            alerts.append(computer_alerts)
    
    return jsonify({
        'total_computers': len(reports),
        'computers_with_alerts': len(alerts),
        'alerts': alerts
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Возвращает статистику"""
    reports = load_reports()
    
    stats = {
        'total_computers': len(reports),
        'total_utm_certificates': 0,
        'total_fns_registry_raw': 0,
        'total_fns_registry_final': 0,
        'expired_utm': 0,
        'expired_fns': 0,
        'warning_utm': 0,
        'warning_fns': 0,
        'valid_utm': 0,
        'valid_fns': 0,
        'computers_without_opensc': 0,
        'computers_without_token': 0,
        'computers_without_utm_certs': 0,
        'computers_without_fns_certs': 0,
        'healthy_computers': 0,
        'problematic_computers': 0,
        'total_deduplicated_fns': 0
    }
    
    for comp_name, data in reports.items():
        has_problems = False
        has_valid_cert = False
        
        # Статистика по компонентам
        if not data.get('opensc_installed'):
            stats['computers_without_opensc'] += 1
        
        if not data.get('rutoken_driver'):
            stats['computers_without_token'] += 1
        
        # УТМ сертификаты
        utm_certs = data.get('utm_certificates', [])
        if isinstance(utm_certs, list):
            stats['total_utm_certificates'] += len(utm_certs)
            
            if len(utm_certs) == 0:
                stats['computers_without_utm_certs'] += 1
            
            for cert in utm_certs:
                if isinstance(cert, dict):
                    status = cert.get('status')
                    if status == 'Expired':
                        stats['expired_utm'] += 1
                        has_problems = True
                    elif status == 'Warning':
                        stats['warning_utm'] += 1
                        has_problems = True
                    elif status == 'Valid':
                        stats['valid_utm'] += 1
                        has_valid_cert = True
        
        # ФНС сертификаты в реестре
        fns_raw = data.get('fns_certificates_raw', [])
        fns_data = data.get('fns_certificates', [])
        
        # Обрабатываем raw данные
        if isinstance(fns_raw, list):
            stats['total_fns_registry_raw'] += len(fns_raw)
        
        # Обрабатываем финальные данные (могут быть списком или объектом)
        fns_final_count = 0
        if isinstance(fns_data, dict):
            fns_final_count = 1
            fns_list = [fns_data]
        elif isinstance(fns_data, list):
            fns_final_count = len(fns_data)
            fns_list = fns_data
        else:
            fns_list = []
        
        stats['total_fns_registry_final'] += fns_final_count
        stats['total_deduplicated_fns'] += (len(fns_raw) - fns_final_count) if isinstance(fns_raw, list) else 0
        
        if fns_final_count == 0:
            stats['computers_without_fns_certs'] += 1
        
        # Проверяем ФНС сертификаты на проблемы
        for cert in fns_list:
            if isinstance(cert, dict):
                status = cert.get('status')
                if status == 'Expired':
                    stats['expired_fns'] += 1
                    has_problems = True
                elif status == 'Warning':
                    stats['warning_fns'] += 1
                    has_problems = True
                elif status == 'Valid':
                    stats['valid_fns'] += 1
                    has_valid_cert = True
        
        # Логика определения проблемности компьютера:
        # Компьютер считается проблемным если:
        # 1. Есть просроченные сертификаты (УТМ или ФНС)
        # ИЛИ
        # 2. Нет ни одного валидного сертификата
        # ИНАЧЕ компьютер считается исправным
        
        if has_problems or not has_valid_cert:
            stats['problematic_computers'] += 1
        else:
            stats['healthy_computers'] += 1
    
    return jsonify(stats)

@app.route('/', methods=['GET'])
def web_interface():
    """Веб-интерфейс для просмотра статуса"""
    reports = load_reports()
    stats = get_stats().json
    
    # Разделяем компьютеры на проблемные и исправные
    problematic_computers = []
    healthy_computers = []
    
    for comp_name, data in reports.items():
        has_problems = False
        has_valid_cert = False
        
        # Проверяем УТМ сертификаты
        utm_certs = data.get('utm_certificates', [])
        if isinstance(utm_certs, list):
            for cert in utm_certs:
                if isinstance(cert, dict):
                    status = cert.get('status')
                    if status in ['Expired', 'Warning']:
                        has_problems = True
                    elif status == 'Valid':
                        has_valid_cert = True
        
        # Проверяем ФНС сертификаты
        fns_data = data.get('fns_certificates', [])
        fns_certs = []
        
        if isinstance(fns_data, dict):
            fns_certs = [fns_data]
        elif isinstance(fns_data, list):
            fns_certs = fns_data
        
        for cert in fns_certs:
            if isinstance(cert, dict):
                status = cert.get('status')
                if status in ['Expired', 'Warning']:
                    has_problems = True
                elif status == 'Valid':
                    has_valid_cert = True
        
        # Определяем статус компьютера
        if has_problems or not has_valid_cert:
            problematic_computers.append(comp_name)
        else:
            healthy_computers.append(comp_name)
    
    # Сортируем по имени
    problematic_computers.sort()
    healthy_computers.sort()
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Мониторинг сертификатов УТМ и ФНС</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }}
        h1, h2, h3 {{ color: #333; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .stats {{ 
            display: flex; 
            gap: 15px; 
            margin: 20px 0; 
            flex-wrap: wrap; 
        }}
        .stat-card {{ 
            padding: 20px; 
            border-radius: 10px; 
            background: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            flex: 1;
            min-width: 150px;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }}
        .stat-card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .stat-card h2 {{ margin: 0; font-size: 32px; }}
        .stat-card .small {{ font-size: 12px; color: #999; }}
        .expired {{ color: #d32f2f; }}
        .warning {{ color: #f57c00; }}
        .valid {{ color: #388e3c; }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            background: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        th, td {{ 
            border: none; 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #e0e0e0;
            vertical-align: top;
        }}
        th {{ 
            background-color: #f8f9fa; 
            font-weight: 600;
            color: #495057;
        }}
        .problem-row {{ background-color: #fff5f5; }}
        .problem-row:hover {{ background-color: #ffe3e3; }}
        .healthy-row {{ background-color: #f0fff4; }}
        .healthy-row:hover {{ background-color: #d9f0e3; }}
        .cert-section {{
            margin-bottom: 15px;
            padding: 10px;
            border-radius: 5px;
            background-color: #f8f9fa;
        }}
        .cert-section h4 {{
            margin: 0 0 10px 0;
            color: #495057;
            font-size: 14px;
        }}
        .cert {{ 
            margin: 8px 0; 
            padding: 10px; 
            border-radius: 5px;
            font-size: 13px;
            border-left: 4px solid;
            background-color: white;
        }}
        .cert.expired {{ 
            border-left-color: #d32f2f;
            background-color: #ffebee;
        }}
        .cert.warning {{ 
            border-left-color: #f57c00;
            background-color: #fff3e0;
        }}
        .cert.valid {{ 
            border-left-color: #388e3c;
            background-color: #e8f5e9;
        }}
        .cert.deduplicated {{
            border-left-color: #9c27b0;
            background-color: #f3e5f5;
            font-style: italic;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 8px;
        }}
        .badge.expired {{ background-color: #d32f2f; color: white; }}
        .badge.warning {{ background-color: #f57c00; color: white; }}
        .badge.valid {{ background-color: #388e3c; color: white; }}
        .badge.dedup {{ background-color: #9c27b0; color: white; }}
        .timestamp {{ color: #6c757d; font-size: 14px; margin-top: 10px; }}
        .section-title {{ 
            margin: 30px 0 15px 0; 
            padding-bottom: 10px; 
            border-bottom: 2px solid #dee2e6;
        }}
        .dedup-stats {{
            font-size: 12px;
            color: #666;
            margin-top: 5px;
            margin-bottom: 10px;
            padding: 5px;
            background-color: #f8f9fa;
            border-radius: 3px;
        }}
        .organization-name {{
            font-weight: 600;
            color: #0066cc;
        }}
        .inn {{
            font-family: monospace;
            color: #666;
        }}
        .full-name {{
            font-weight: 600;
            color: #2c3e50;
            font-size: 14px;
        }}
        .empty-message {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-style: italic;
            background-color: #f9f9f9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Мониторинг сертификатов УТМ и ФНС</h1>
        <p class="timestamp">Обновлено: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-card">
                <h3>📊 Всего компьютеров</h3>
                <h2>{stats['total_computers']}</h2>
            </div>
            <div class="stat-card">
                <h3>📄 УТМ сертификатов</h3>
                <h2>{stats['total_utm_certificates']}</h2>
            </div>
            <div class="stat-card">
                <h3>📄 ФНС сертификатов</h3>
                <h2>{stats['total_fns_registry_final']}</h2>
                <div class="small">(найдено: {stats['total_fns_registry_raw']}, дублей: {stats['total_deduplicated_fns']})</div>
            </div>
            <div class="stat-card" style="background: #ffebee;">
                <h3>❌ Просрочено УТМ</h3>
                <h2 class="expired">{stats['expired_utm']}</h2>
            </div>
            <div class="stat-card" style="background: #ffebee;">
                <h3>❌ Просрочено ФНС</h3>
                <h2 class="expired">{stats['expired_fns']}</h2>
            </div>
            <div class="stat-card" style="background: #fff3e0;">
                <h3>⚠️ Скоро УТМ</h3>
                <h2 class="warning">{stats['warning_utm']}</h2>
            </div>
            <div class="stat-card" style="background: #fff3e0;">
                <h3>⚠️ Скоро ФНС</h3>
                <h2 class="warning">{stats['warning_fns']}</h2>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card" style="background: #e8f5e9;">
                <h3>✅ Исправных ПК</h3>
                <h2 class="valid">{stats['healthy_computers']}</h2>
            </div>
            <div class="stat-card" style="background: #ffebee;">
                <h3>⚠️ Проблемных ПК</h3>
                <h2 class="expired">{stats['problematic_computers']}</h2>
            </div>
            <div class="stat-card">
                <h3>🔧 Без OpenSC</h3>
                <h2>{stats['computers_without_opensc']}</h2>
            </div>
            <div class="stat-card">
                <h3>💿 Без драйвера</h3>
                <h2>{stats['computers_without_token']}</h2>
            </div>
        </div>
        
        <h2 class="section-title">⚠️ Проблемные компьютеры ({len(problematic_computers)})</h2>
        <table>
            <thead>
                <tr>
                    <th>Компьютер</th>
                    <th>OpenSC</th>
                    <th>Драйвер</th>
                    <th>Последний отчет</th>
                    <th>УТМ сертификаты</th>
                    <th>ФНС сертификаты</th>
                </tr>
            </thead>
            <tbody>
"""
    
    # Проблемные компьютеры
    if len(problematic_computers) > 0:
        for comp_name in problematic_computers:
            data = reports[comp_name]
            last_seen = datetime.fromisoformat(data['received_at']).strftime('%d.%m.%Y %H:%M')
            opensc_status = "✅" if data.get('opensc_installed') else "❌"
            driver_status = "✅" if data.get('rutoken_driver') else "❌"
            
            # УТМ сертификаты
            utm_certs_html = ""
            utm_certs = data.get('utm_certificates', [])
            if isinstance(utm_certs, list):
                for cert in utm_certs:
                    if isinstance(cert, dict):
                        status_class = cert.get('status', '').lower()
                        days_left = cert.get('days_left', 0)
                        badge = f"<span class='badge {status_class}'>{cert.get('status', '')}</span>"
                        
                        utm_certs_html += f"<div class='cert {status_class}'>"
                        utm_certs_html += f"<strong>ID:</strong> {cert.get('id', '')[:20]}...<br>"
                        utm_certs_html += f"<strong>Истекает:</strong> {cert.get('expiry_date', '')}<br>"
                        utm_certs_html += f"<strong>Осталось:</strong> {days_left} дн. {badge}"
                        utm_certs_html += "</div>"
            
            if not utm_certs_html:
                utm_certs_html = "<div class='cert warning'>❌ Нет сертификатов УТМ</div>"
            
            # ФНС сертификаты
            fns_certs_html = ""
            fns_data = data.get('fns_certificates', [])
            fns_certs = []
            
            if isinstance(fns_data, dict):
                fns_certs = [fns_data]
            elif isinstance(fns_data, list):
                fns_certs = fns_data
            
            # Статистика дедупликации
            dedup_stats = data.get('deduplication_stats', {})
            fns_raw_count = dedup_stats.get('fns_original_count', 0)
            
            if fns_raw_count > len(fns_certs):
                fns_certs_html += f"<div class='dedup-stats'>📊 Найдено: {fns_raw_count}, после дедупликации: {len(fns_certs)}</div>"
            
            for cert in fns_certs:
                if isinstance(cert, dict):
                    status_class = cert.get('status', '').lower()
                    days_left = cert.get('days_left', 0)
                    organization = cert.get('organization', '')
                    inn = cert.get('inn', '')
                    full_name = cert.get('full_name', '')
                    badge = f"<span class='badge {status_class}'>{cert.get('status', '')}</span>"
                    
                    fns_certs_html += f"<div class='cert {status_class}'>"
                    
                    if full_name:
                        fns_certs_html += f"<div class='full-name'>{full_name}</div>"
                    
                    if organization and organization != full_name:
                        fns_certs_html += f"<div class='organization-name'>{organization}</div>"
                    
                    if inn:
                        fns_certs_html += f"<div class='inn'>ИНН: {inn}</div>"
                    
                    fns_certs_html += f"<div><strong>Истекает:</strong> {cert.get('expiry_date', '')}</div>"
                    fns_certs_html += f"<div><strong>Осталось:</strong> {days_left} дн. {badge}</div>"
                    fns_certs_html += f"<div><small>Хранилище: {cert.get('store', '')}</small></div>"
                    fns_certs_html += "</div>"
            
            if not fns_certs_html and fns_raw_count > 0:
                fns_certs_html += "<div class='cert deduplicated'>✅ Все сертификаты продублированы, оставлены только свежие</div>"
            elif not fns_certs_html:
                fns_certs_html = "<div class='cert warning'>❌ Нет ФНС сертификатов</div>"
            
            html += f"""
                    <tr class="problem-row">
                        <td><strong>{comp_name}</strong></td>
                        <td style="text-align: center; font-size: 20px;">{opensc_status}</td>
                        <td style="text-align: center; font-size: 20px;">{driver_status}</td>
                        <td>{last_seen}</td>
                        <td>{utm_certs_html}</td>
                        <td>{fns_certs_html}</td>
                    </tr>
            """
    else:
        html += """
                <tr>
                    <td colspan="6" class="empty-message">
                        ✅ Нет проблемных компьютеров. Все системы работают нормально.
                    </td>
                </tr>
        """
    
    html += f"""
            </tbody>
        </table>
        
        <h2 class="section-title">✅ Исправные компьютеры ({len(healthy_computers)})</h2>
        <table>
            <thead>
                <tr>
                    <th>Компьютер</th>
                    <th>OpenSC</th>
                    <th>Драйвер</th>
                    <th>Последний отчет</th>
                    <th>УТМ сертификаты</th>
                    <th>ФНС сертификаты</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Исправные компьютеры
    if len(healthy_computers) > 0:
        for comp_name in healthy_computers:
            data = reports[comp_name]
            last_seen = datetime.fromisoformat(data['received_at']).strftime('%d.%m.%Y %H:%M')
            opensc_status = "✅" if data.get('opensc_installed') else "❌"
            driver_status = "✅" if data.get('rutoken_driver') else "❌"
            
            # УТМ сертификаты
            utm_certs_html = ""
            utm_certs = data.get('utm_certificates', [])
            if isinstance(utm_certs, list):
                for cert in utm_certs:
                    if isinstance(cert, dict):
                        status_class = cert.get('status', '').lower()
                        days_left = cert.get('days_left', 0)
                        badge = f"<span class='badge {status_class}'>{cert.get('status', '')}</span>"
                        
                        utm_certs_html += f"<div class='cert {status_class}'>"
                        utm_certs_html += f"<strong>ID:</strong> {cert.get('id', '')[:20]}...<br>"
                        utm_certs_html += f"<strong>Истекает:</strong> {cert.get('expiry_date', '')}<br>"
                        utm_certs_html += f"<strong>Осталось:</strong> {days_left} дн. {badge}"
                        utm_certs_html += "</div>"
            
            if not utm_certs_html:
                utm_certs_html = "<div class='cert'>📄 Нет сертификатов УТМ</div>"
            
            # ФНС сертификаты
            fns_certs_html = ""
            fns_data = data.get('fns_certificates', [])
            fns_certs = []
            
            if isinstance(fns_data, dict):
                fns_certs = [fns_data]
            elif isinstance(fns_data, list):
                fns_certs = fns_data
            
            dedup_stats = data.get('deduplication_stats', {})
            fns_raw_count = dedup_stats.get('fns_original_count', 0)
            
            if fns_raw_count > len(fns_certs):
                fns_certs_html += f"<div class='dedup-stats'>📊 Найдено: {fns_raw_count}, после дедупликации: {len(fns_certs)}</div>"
            
            for cert in fns_certs:
                if isinstance(cert, dict):
                    status_class = cert.get('status', '').lower()
                    days_left = cert.get('days_left', 0)
                    organization = cert.get('organization', '')
                    inn = cert.get('inn', '')
                    full_name = cert.get('full_name', '')
                    badge = f"<span class='badge {status_class}'>{cert.get('status', '')}</span>"
                    
                    fns_certs_html += f"<div class='cert {status_class}'>"
                    
                    if full_name:
                        fns_certs_html += f"<div class='full-name'>{full_name}</div>"
                    
                    if organization and organization != full_name:
                        fns_certs_html += f"<div class='organization-name'>{organization}</div>"
                    
                    if inn:
                        fns_certs_html += f"<div class='inn'>ИНН: {inn}</div>"
                    
                    fns_certs_html += f"<div><strong>Истекает:</strong> {cert.get('expiry_date', '')} {badge}</div>"
                    fns_certs_html += "</div>"
            
            if not fns_certs_html:
                fns_certs_html = "<div class='cert'>📄 Нет ФНС сертификатов</div>"
            
            html += f"""
                    <tr class="healthy-row">
                        <td><strong>{comp_name}</strong></td>
                        <td style="text-align: center; font-size: 20px;">{opensc_status}</td>
                        <td style="text-align: center; font-size: 20px;">{driver_status}</td>
                        <td>{last_seen}</td>
                        <td>{utm_certs_html}</td>
                        <td>{fns_certs_html}</td>
                    </tr>
            """
    else:
        html += """
                <tr>
                    <td colspan="6" class="empty-message">
                        ❌ Нет исправных компьютеров. Все системы имеют проблемы.
                    </td>
                </tr>
        """
    
    html += f"""
            </tbody>
        </table>
        
        <div class="api-links">
            <h3>📡 API Endpoints</h3>
            <p>
                <a href="/api/reports" target="_blank">📊 /api/reports</a> - все отчеты (JSON)
                <a href="/api/stats" target="_blank">📈 /api/stats</a> - статистика (JSON)
                <a href="/api/check_alerts" target="_blank">⚠️ /api/check_alerts</a> - проблемы (JSON)
            </p>
        </div>
        
        <div style="margin-top: 20px; color: #6c757d; font-size: 12px; text-align: center;">
            Порог предупреждения: {ALERT_DAYS} дней | 
            Дедупликация: оставляем только самый свежий сертификат для каждой организации/ИНН |
            Данные сохраняются в папке utm_cert_data
        </div>
    </div>
</body>
</html>
    """
    
    return html

if __name__ == '__main__':
    print("="*70)
    print("🔐 СЕРВЕР МОНИТОРИНГА СЕРТИФИКАТОВ УТМ И ФНС")
    print("="*70)
    print(f"📁 Данные сохраняются в: {DATA_DIR.absolute()}")
    print(f"⚠️  Порог предупреждения: {ALERT_DAYS} дней")
    print("📊 Дедупликация: оставляем только свежие сертификаты для каждой организации")
    print("="*70)
    print("🚀 Запуск сервера...")
    print("🌐 Веб-интерфейс: http://localhost:5000")
    print("📡 API: http://localhost:5000/api/...")
    print("="*70)
    print("Нажмите Ctrl+C для остановки")
    print("="*70)
    
    app.run(host='0.0.0.0', port=5000, debug=True)