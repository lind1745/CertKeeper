# utm_cert_server.py
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from datetime import datetime
import json
import os
from pathlib import Path
from functools import wraps
import hashlib
import secrets

app = Flask(__name__)
# Генерируем случайный секретный ключ при каждом запуске
app.secret_key = secrets.token_hex(32)

# Настройки
DATA_DIR = Path("utm_cert_data")
DATA_DIR.mkdir(exist_ok=True)
REPORT_FILE = DATA_DIR / "all_reports.json"
ALERT_DAYS = 30  # За сколько дней предупреждать

# Настройки авторизации
USERS_FILE = DATA_DIR / "users.json"

def init_users_file():
    """Инициализирует файл с пользователями, если его нет"""
    if not USERS_FILE.exists():
        # Создаем пользователя по умолчанию (admin/admin)
        default_users = {
            "admin": {
                "password_hash": hashlib.sha256("admin".encode()).hexdigest(),
                "name": "Администратор",
                "created_at": datetime.now().isoformat()
            }
        }
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_users, f, ensure_ascii=False, indent=2)
        print("📝 Создан пользователь по умолчанию: admin/admin")

def load_users():
    """Загружает пользователей из файла"""
    if USERS_FILE.exists():
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Сохраняет пользователей в файл"""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def check_password(username, password):
    """Проверяет логин и пароль"""
    users = load_users()
    if username in users:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return users[username]["password_hash"] == password_hash
    return False

def login_required(f):
    """Декоратор для проверки авторизации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def api_auth_required(f):
    """Декоратор для проверки авторизации в API"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

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

def search_in_reports(reports, query):
    """
    Ищет по:
    - ИНН (без учета регистра)
    - ФИО (без учета регистра)
    - Названию компьютера (без учета регистра)
    Возвращает список компьютеров, где найдены совпадения
    """
    if not query or len(query) < 2:
        return []
    
    query_lower = query.lower().strip()
    results = []
    
    for comp_name, data in reports.items():
        computer_result = {
            'computer_name': comp_name,
            'matches': []
        }
        
        # Поиск по имени компьютера
        if query_lower in comp_name.lower():
            computer_result['matches'].append({
                'type': 'computer',
                'field': 'computer_name',
                'value': comp_name
            })
        
        # Ищем в ФНС сертификатах
        fns_data = data.get('fns_certificates', [])
        fns_certs = []
        
        if isinstance(fns_data, dict):
            fns_certs = [fns_data]
        elif isinstance(fns_data, list):
            fns_certs = fns_data
        
        for cert in fns_certs:
            if isinstance(cert, dict):
                # Поиск по ФИО
                full_name = cert.get('full_name', '')
                if full_name and query_lower in full_name.lower():
                    computer_result['matches'].append({
                        'type': 'fns',
                        'field': 'full_name',
                        'value': full_name,
                        'cert_data': cert
                    })
                
                # Поиск по организации
                organization = cert.get('organization', '')
                if organization and query_lower in organization.lower():
                    computer_result['matches'].append({
                        'type': 'fns',
                        'field': 'organization',
                        'value': organization,
                        'cert_data': cert
                    })
                
                # Поиск по ИНН
                inn = cert.get('inn', '')
                if inn and query in inn:  # ИНН ищем точное вхождение
                    computer_result['matches'].append({
                        'type': 'fns',
                        'field': 'inn',
                        'value': inn,
                        'cert_data': cert
                    })
        
        # Если есть совпадения, добавляем компьютер в результаты
        if computer_result['matches']:
            results.append(computer_result)
    
    return results

# Страница логина
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Страница входа"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if check_password(username, password):
            session['username'] = username
            users = load_users()
            session['user_name'] = users[username].get('name', username)
            return redirect(url_for('web_interface'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Неверный логин или пароль")
    
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    """Выход из системы"""
    session.pop('username', None)
    session.pop('user_name', None)
    return redirect(url_for('login_page'))

# API для смены пароля
@app.route('/api/change-password', methods=['POST'])
@api_auth_required
def change_password():
    """Изменяет пароль текущего пользователя"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({"error": "Current password and new password required"}), 400
    
    if len(new_password) < 3:
        return jsonify({"error": "New password must be at least 3 characters"}), 400
    
    username = session['username']
    users = load_users()
    
    # Проверяем текущий пароль
    current_hash = hashlib.sha256(current_password.encode()).hexdigest()
    if users[username]["password_hash"] != current_hash:
        return jsonify({"error": "Current password is incorrect"}), 401
    
    # Устанавливаем новый пароль
    users[username]["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()
    save_users(users)
    
    return jsonify({"status": "ok", "message": "Password changed successfully"})

# API для управления пользователями (скрытое, только для админа)
@app.route('/api/users', methods=['GET'])
@api_auth_required
def get_users():
    """Возвращает список пользователей"""
    if session['username'] != 'admin':
        return jsonify({"error": "Access denied"}), 403
    
    users = load_users()
    safe_users = {}
    for username, data in users.items():
        safe_users[username] = {
            'name': data.get('name', ''),
            'created_at': data.get('created_at', '')
        }
    return jsonify(safe_users)

@app.route('/api/users', methods=['POST'])
@api_auth_required
def create_user():
    """Создает нового пользователя"""
    if session['username'] != 'admin':
        return jsonify({"error": "Access denied"}), 403
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name', username)
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    users = load_users()
    if username in users:
        return jsonify({"error": "User already exists"}), 400
    
    users[username] = {
        'password_hash': hashlib.sha256(password.encode()).hexdigest(),
        'name': name,
        'created_at': datetime.now().isoformat()
    }
    
    save_users(users)
    return jsonify({"status": "ok", "message": f"User {username} created"})

@app.route('/api/users/<username>', methods=['DELETE'])
@api_auth_required
def delete_user(username):
    """Удаляет пользователя"""
    if session['username'] != 'admin':
        return jsonify({"error": "Access denied"}), 403
    
    if username == 'admin':
        return jsonify({"error": "Cannot delete admin user"}), 400
    
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        return jsonify({"status": "ok", "message": f"User {username} deleted"})
    
    return jsonify({"error": "User not found"}), 404

@app.route('/api/users/<username>/password', methods=['PUT'])
@api_auth_required
def change_user_password(username):
    """Изменяет пароль пользователя (для админа)"""
    if session['username'] != 'admin' and session['username'] != username:
        return jsonify({"error": "Access denied"}), 403
    
    data = request.get_json()
    new_password = data.get('password')
    
    if not new_password:
        return jsonify({"error": "New password required"}), 400
    
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    
    users[username]['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
    save_users(users)
    
    return jsonify({"status": "ok", "message": f"Password changed for {username}"})

# API endpoint для поиска
@app.route('/api/search', methods=['GET'])
@api_auth_required
def search_api():
    """API для поиска по ИНН/ФИО/компьютерам"""
    query = request.args.get('q', '')
    if len(query) < 2:
        return jsonify({"error": "Query too short"}), 400
    
    reports = load_reports()
    results = search_in_reports(reports, query)
    
    return jsonify({
        'query': query,
        'total_results': len(results),
        'results': results
    })

@app.route('/api/report', methods=['POST'])
def receive_report():
    """Принимает отчет от клиента (не требует авторизации)"""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No data"}), 400
        
        computer_name = data.get('computer_name')
        if not computer_name:
            return jsonify({"error": "No computer_name"}), 400
        
        data['received_at'] = datetime.now().isoformat()
        
        reports = load_reports()
        reports[computer_name] = data
        
        computer_file = DATA_DIR / f"{computer_name}.json"
        with open(computer_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        save_reports(reports)
        
        print(f"[{datetime.now().strftime('%d.%m.%Y %H:%M:%S')}] Получен отчет от {computer_name}")
        print(f"  УТМ сертификатов: {len(data.get('utm_certificates', []))}")
        
        fns_certs = data.get('fns_certificates', [])
        if isinstance(fns_certs, dict):
            print(f"  ФНС сертификатов (объект): 1")
        elif isinstance(fns_certs, list):
            print(f"  ФНС сертификатов (список): {len(fns_certs)}")
        else:
            print(f"  ФНС сертификатов: нет")
        
        dedup_stats = data.get('deduplication_stats', {})
        if dedup_stats:
            print(f"  Дедупликация ФНС: было {dedup_stats.get('fns_original_count', 0)} -> стало {dedup_stats.get('fns_final_count', 0)}")
        
        return jsonify({"status": "ok", "received": computer_name})
    
    except Exception as e:
        print(f"Ошибка: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports', methods=['GET'])
@api_auth_required
def get_all_reports():
    """Возвращает все отчеты"""
    reports = load_reports()
    return jsonify(reports)

@app.route('/api/report/<computer_name>', methods=['GET'])
@api_auth_required
def get_computer_report(computer_name):
    """Возвращает отчет конкретного компьютера"""
    reports = load_reports()
    if computer_name in reports:
        return jsonify(reports[computer_name])
    return jsonify({"error": "Not found"}), 404

@app.route('/api/check_alerts', methods=['GET'])
@api_auth_required
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
        
        if not data.get('opensc_installed'):
            computer_alerts['problems'].append('OpenSC not installed')
        
        if not data.get('rutoken_driver'):
            computer_alerts['problems'].append('Rutoken driver not installed')
        
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
@api_auth_required
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
        
        if not data.get('opensc_installed'):
            stats['computers_without_opensc'] += 1
        
        if not data.get('rutoken_driver'):
            stats['computers_without_token'] += 1
        
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
        
        fns_raw = data.get('fns_certificates_raw', [])
        fns_data = data.get('fns_certificates', [])
        
        if isinstance(fns_raw, list):
            stats['total_fns_registry_raw'] += len(fns_raw)
        
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
        
        if has_problems or not has_valid_cert:
            stats['problematic_computers'] += 1
        else:
            stats['healthy_computers'] += 1
    
    return jsonify(stats)

@app.route('/', methods=['GET'])
@login_required
def web_interface():
    """Веб-интерфейс для просмотра статуса"""
    reports = load_reports()
    stats = get_stats().json
    
    search_query = request.args.get('search', '')
    search_results = []
    if search_query and len(search_query) >= 2:
        search_results = search_in_reports(reports, search_query)
    
    # Получаем компьютер для прокрутки (если есть)
    scroll_to = request.args.get('scroll_to', '')
    
    problematic_computers = []
    healthy_computers = []
    
    for comp_name, data in reports.items():
        has_problems = False
        has_valid_cert = False
        
        utm_certs = data.get('utm_certificates', [])
        if isinstance(utm_certs, list):
            for cert in utm_certs:
                if isinstance(cert, dict):
                    status = cert.get('status')
                    if status in ['Expired', 'Warning']:
                        has_problems = True
                    elif status == 'Valid':
                        has_valid_cert = True
        
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
        
        if has_problems or not has_valid_cert:
            problematic_computers.append(comp_name)
        else:
            healthy_computers.append(comp_name)
    
    problematic_computers.sort()
    healthy_computers.sort()
    
    html = generate_html(stats, reports, problematic_computers, healthy_computers, 
                        search_query, search_results, session.get('user_name', 'User'), 
                        session.get('username', ''), scroll_to)
    
    return html

def generate_html(stats, reports, problematic_computers, healthy_computers, 
                 search_query, search_results, user_name, username, scroll_to):
    """Генерирует HTML страницу"""
    
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
            scroll-behavior: smooth;
        }}
        h1, h2, h3 {{ color: #333; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .user-info {{
            background: white;
            padding: 10px 20px;
            border-radius: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .user-menu {{
            position: relative;
            display: inline-block;
        }}
        .user-menu-button {{
            background: none;
            border: none;
            color: #333;
            font-size: 16px;
            cursor: pointer;
            padding: 5px 10px;
            border-radius: 5px;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .user-menu-button:hover {{
            background-color: #f0f0f0;
        }}
        .user-menu-content {{
            display: none;
            position: absolute;
            right: 0;
            background-color: white;
            min-width: 200px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
            border-radius: 8px;
            z-index: 1000;
            margin-top: 5px;
        }}
        .user-menu-content a, .user-menu-content button {{
            color: #333;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
            width: 100%;
            text-align: left;
            border: none;
            background: none;
            font-size: 14px;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
        }}
        .user-menu-content a:hover, .user-menu-content button:hover {{
            background-color: #f5f5f5;
        }}
        .user-menu-content a:last-child, .user-menu-content button:last-child {{
            border-bottom: none;
        }}
        .user-menu:hover .user-menu-content {{
            display: block;
        }}
        .logout-link {{
            color: #dc3545 !important;
        }}
        
        /* Модальное окно */
        .modal {{
            display: none;
            position: fixed;
            z-index: 9999;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            animation: fadeIn 0.3s;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        .modal-content {{
            background-color: white;
            margin: 15% auto;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            animation: slideIn 0.3s;
        }}
        @keyframes slideIn {{
            from {{
                transform: translateY(-50px);
                opacity: 0;
            }}
            to {{
                transform: translateY(0);
                opacity: 1;
            }}
        }}
        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}
        .modal-header h3 {{
            margin: 0;
            color: #333;
        }}
        .close-modal {{
            font-size: 24px;
            cursor: pointer;
            color: #999;
            transition: color 0.2s;
        }}
        .close-modal:hover {{
            color: #333;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        .form-group label {{
            display: block;
            margin-bottom: 5px;
            color: #666;
            font-weight: 600;
            font-size: 14px;
        }}
        .form-group input {{
            width: 100%;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
            transition: border-color 0.2s;
        }}
        .form-group input:focus {{
            outline: none;
            border-color: #0066cc;
        }}
        .password-button {{
            width: 100%;
            padding: 12px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .password-button:hover {{
            background: #0052a3;
        }}
        .message {{
            margin-top: 15px;
            padding: 10px;
            border-radius: 5px;
            display: none;
        }}
        .message.success {{
            background: #e8f5e9;
            color: #388e3c;
            border: 1px solid #a5d6a7;
            display: block;
        }}
        .message.error {{
            background: #ffebee;
            color: #d32f2f;
            border: 1px solid #ef9a9a;
            display: block;
        }}
        
        .search-box {{
            margin: 20px 0;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .search-form {{
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .search-input {{
            flex: 1;
            min-width: 200px;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }}
        .search-input:focus {{
            outline: none;
            border-color: #0066cc;
        }}
        .search-button {{
            padding: 12px 24px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .search-button:hover {{
            background: #0052a3;
        }}
        .reset-button {{
            padding: 12px 24px;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }}
        .reset-button:hover {{
            background: #5a6268;
        }}
        .search-results {{
            margin-top: 15px;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 8px;
        }}
        .search-match {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #0066cc;
            transition: all 0.2s;
        }}
        .search-match:hover {{
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }}
        .computer-link {{
            color: #0066cc;
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
            display: block;
        }}
        .computer-link:hover {{
            text-decoration: underline;
        }}
        .computer-link .badge {{
            margin-right: 8px;
        }}
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
        .computer-row {{
            scroll-margin-top: 20px;
            transition: background-color 0.3s;
        }}
        .computer-row.highlight {{
            background-color: #fff3cd !important;
            box-shadow: 0 0 0 3px #ffc107;
        }}
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
        .badge.computer {{ background-color: #0066cc; color: white; }}
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
        .highlight {{
            background-color: #fff3cd;
            font-weight: 600;
        }}
    </style>
    <script>
        // Функция для прокрутки к компьютеру при загрузке страницы
        window.onload = function() {{
            const hash = window.location.hash;
            if (hash) {{
                const element = document.querySelector(hash);
                if (element) {{
                    element.classList.add('highlight');
                    setTimeout(() => {{
                        element.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    }}, 100);
                    setTimeout(() => {{
                        element.classList.remove('highlight');
                    }}, 3000);
                }}
            }}
        }}
        
        // Функция для перехода к компьютеру
        function scrollToComputer(computerName) {{
            const element = document.getElementById('computer-' + computerName.replace(/[^a-zA-Z0-9]/g, '-'));
            if (element) {{
                element.classList.add('highlight');
                element.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                setTimeout(() => {{
                    element.classList.remove('highlight');
                }}, 3000);
            }}
        }}
        
        // Функции для модального окна смены пароля
        function openPasswordModal() {{
            document.getElementById('passwordModal').style.display = 'block';
        }}
        
        function closePasswordModal() {{
            document.getElementById('passwordModal').style.display = 'none';
            document.getElementById('current_password').value = '';
            document.getElementById('new_password').value = '';
            document.getElementById('confirm_password').value = '';
            document.getElementById('passwordMessage').style.display = 'none';
        }}
        
        function changePassword() {{
            const current = document.getElementById('current_password').value;
            const newPass = document.getElementById('new_password').value;
            const confirm = document.getElementById('confirm_password').value;
            const messageDiv = document.getElementById('passwordMessage');
            
            if (!current || !newPass || !confirm) {{
                messageDiv.className = 'message error';
                messageDiv.textContent = 'Заполните все поля';
                return;
            }}
            
            if (newPass !== confirm) {{
                messageDiv.className = 'message error';
                messageDiv.textContent = 'Новый пароль и подтверждение не совпадают';
                return;
            }}
            
            if (newPass.length < 3) {{
                messageDiv.className = 'message error';
                messageDiv.textContent = 'Пароль должен быть не менее 3 символов';
                return;
            }}
            
            fetch('/api/change-password', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                }},
                body: JSON.stringify({{
                    current_password: current,
                    new_password: newPass
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.error) {{
                    messageDiv.className = 'message error';
                    messageDiv.textContent = data.error;
                }} else {{
                    messageDiv.className = 'message success';
                    messageDiv.textContent = 'Пароль успешно изменен!';
                    setTimeout(() => {{
                        closePasswordModal();
                    }}, 2000);
                }}
            }})
            .catch(error => {{
                messageDiv.className = 'message error';
                messageDiv.textContent = 'Ошибка при смене пароля';
            }});
        }}
        
        // Закрытие модального окна по клику вне его
        window.onclick = function(event) {{
            const modal = document.getElementById('passwordModal');
            if (event.target == modal) {{
                closePasswordModal();
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Мониторинг сертификатов УТМ и ФНС</h1>
            <div class="user-info">
                <span>👤 {user_name}</span>
                <div class="user-menu">
                    <button class="user-menu-button">⚙️ Настройки ▼</button>
                    <div class="user-menu-content">
                        <button onclick="openPasswordModal()">🔑 Сменить пароль</button>
                        <a href="/logout" class="logout-link">🚪 Выйти</a>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Модальное окно смены пароля -->
        <div id="passwordModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>🔑 Смена пароля</h3>
                    <span class="close-modal" onclick="closePasswordModal()">&times;</span>
                </div>
                <div class="form-group">
                    <label>Текущий пароль</label>
                    <input type="password" id="current_password" placeholder="Введите текущий пароль">
                </div>
                <div class="form-group">
                    <label>Новый пароль</label>
                    <input type="password" id="new_password" placeholder="Введите новый пароль">
                </div>
                <div class="form-group">
                    <label>Подтверждение</label>
                    <input type="password" id="confirm_password" placeholder="Подтвердите новый пароль">
                </div>
                <button class="password-button" onclick="changePassword()">Сменить пароль</button>
                <div id="passwordMessage" class="message"></div>
            </div>
        </div>
        
        <p class="timestamp">Обновлено: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
        
        <!-- Поиск -->
        <div class="search-box">
            <form class="search-form" method="get" action="/">
                <input type="text" class="search-input" name="search" 
                       placeholder="Поиск по компьютерам, ИНН или ФИО (без учета регистра)..." 
                       value="{search_query if search_query else ''}"
                       minlength="2">
                <button type="submit" class="search-button">🔍 Найти</button>
                {f'<a href="/" class="reset-button">✕ Сбросить</a>' if search_query else ''}
            </form>
            
            {generate_search_results(search_results, search_query)}
        </div>
        
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
    
    if len(problematic_computers) > 0:
        for comp_name in problematic_computers:
            data = reports[comp_name]
            html += generate_computer_row(comp_name, data, scroll_to)
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
    
    if len(healthy_computers) > 0:
        for comp_name in healthy_computers:
            data = reports[comp_name]
            html += generate_computer_row(comp_name, data, scroll_to)
    else:
        html += """
                <tr>
                    <td colspan="6" class="empty-message">
                        ❌ Нет исправных компьютеров. Все системы имеют проблемы.
                    </td>
                </tr>
        """
    
    html += """
            </tbody>
        </table>
        
        <div class="api-links">
            <h3>📡 API Endpoints (требуют авторизации)</h3>
            <p>
                <a href="/api/reports" target="_blank">📊 /api/reports</a> - все отчеты (JSON)<br>
                <a href="/api/stats" target="_blank">📈 /api/stats</a> - статистика (JSON)<br>
                <a href="/api/check_alerts" target="_blank">⚠️ /api/check_alerts</a> - проблемы (JSON)<br>
                <a href="/api/search?q=тест" target="_blank">🔍 /api/search?q=...</a> - поиск по ИНН/ФИО/компьютерам
            </p>
        </div>
        
        <div style="margin-top: 20px; color: #6c757d; font-size: 12px; text-align: center;">
            Порог предупреждения: """ + str(ALERT_DAYS) + """ дней | 
            Дедупликация: оставляем только самый свежий сертификат для каждой организации/ИНН |
            Данные сохраняются в папке utm_cert_data
        </div>
    </div>
</body>
</html>
    """
    
    return html

def generate_computer_row(comp_name, data, scroll_to=None):
    """Генерирует строку таблицы для компьютера"""
    last_seen = datetime.fromisoformat(data['received_at']).strftime('%d.%m.%Y %H:%M')
    opensc_status = "✅" if data.get('opensc_installed') else "❌"
    driver_status = "✅" if data.get('rutoken_driver') else "❌"
    
    # ИСПРАВЛЕНО: выносим replace с обратным слешем за пределы f-строки
    clean_name = comp_name.replace(' ', '-').replace('.', '-').replace('/', '-')
    clean_name = clean_name.replace('\\', '-')
    anchor_id = f"computer-{clean_name}"
    
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
            
            fns_certs_html += f"<div><strong>Истекает:</strong> {cert.get('expiry_date', '')}<br>"
            fns_certs_html += f"<strong>Осталось:</strong> {days_left} дн. {badge}</div>"
            fns_certs_html += f"<div><small>Хранилище: {cert.get('store', '')}</small></div>"
            fns_certs_html += "</div>"
    
    if not fns_certs_html and fns_raw_count > 0:
        fns_certs_html += "<div class='cert deduplicated'>✅ Все сертификаты продублированы, оставлены только свежие</div>"
    elif not fns_certs_html:
        fns_certs_html = "<div class='cert warning'>❌ Нет ФНС сертификатов</div>"
    
    row_class = "problem-row" if "❌" in utm_certs_html or "expired" in utm_certs_html or "warning" in fns_certs_html else "healthy-row"
    highlight_class = " highlight" if scroll_to and scroll_to == comp_name else ""
    
    return f"""
                    <tr id="{anchor_id}" class="computer-row {row_class}{highlight_class}">
                        <td><strong><a href="#{anchor_id}" style="color: #0066cc; text-decoration: none;" onclick="scrollToComputer('{comp_name}'); return false;">{comp_name}</a></strong></td>
                        <td style="text-align: center; font-size: 20px;">{opensc_status}</td>
                        <td style="text-align: center; font-size: 20px;">{driver_status}</td>
                        <td>{last_seen}</td>
                        <td>{utm_certs_html}</td>
                        <td>{fns_certs_html}</td>
                    </tr>
            """

def generate_search_results(results, query):
    """Генерирует HTML для результатов поиска"""
    if not query or len(query) < 2:
        return ""
    
    if not results:
        return f"""
        <div class="search-results">
            <strong>🔍 Результаты поиска по запросу "{query}":</strong><br>
            Ничего не найдено
        </div>
        """
    
    html = f"""
    <div class="search-results">
        <strong>🔍 Результаты поиска по запросу "{query}":</strong> найдено на {len(results)} компьютерах
    """
    
    for result in results:
        # ИСПРАВЛЕНО: выносим replace с обратным слешем за пределы f-строки
        clean_name = result['computer_name'].replace(' ', '-').replace('.', '-').replace('/', '-')
        clean_name = clean_name.replace('\\', '-')
        anchor_id = f"computer-{clean_name}"
        
        html += f"""
        <div class="search-match">
            <a href="#{anchor_id}" class="computer-link" onclick="scrollToComputer('{result['computer_name']}'); return false;">
                <span class="badge computer">💻</span> {result['computer_name']}
            </a>
        """
        
        for match in result['matches']:
            if match['type'] == 'computer':
                html += f"""
                <div style="margin-left: 20px; margin-top: 5px; color: #666;">
                    <small>Имя компьютера: {match['value']}</small>
                </div>
                """
            else:
                cert = match['cert_data']
                html += f"""
                <div style="margin-left: 20px; margin-top: 5px;">
                    <span class="badge valid">ФНС</span>
                    <strong>{match['field']}:</strong> {match['value']}<br>
                    <small>Истекает: {cert.get('expiry_date', '')}</small>
                </div>
                """
        
        html += "</div>"
    
    html += "</div>"
    return html

# Шаблон страницы логина
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Вход в систему мониторинга</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            margin: 0 0 30px 0;
            color: #333;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #666;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #0066cc;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        button:hover {
            background: #0052a3;
        }
        .error {
            background: #ffebee;
            color: #d32f2f;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        .info {
            margin-top: 20px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Мониторинг сертификатов</h1>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="post">
            <div class="form-group">
                <label>Логин</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label>Пароль</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Войти</button>
        </form>
        
        <div class="info">
            По умолчанию: admin/admin<br>
            Рекомендуется сменить пароль!
        </div>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    print("="*70)
    print("🔐 СЕРВЕР МОНИТОРИНГА СЕРТИФИКАТОВ УТМ И ФНС")
    print("="*70)
    print(f"📁 Данные сохраняются в: {DATA_DIR.absolute()}")
    print(f"👤 Файл пользователей: {USERS_FILE.absolute()}")
    print(f"⚠️  Порог предупреждения: {ALERT_DAYS} дней")
    print("📊 Дедупликация: оставляем только свежие сертификаты для каждой организации")
    print("="*70)
    
    init_users_file()
    
    print("🚀 Запуск сервера...")
    print("🌐 Веб-интерфейс: http://localhost:5000")
    print("📡 API: http://localhost:5000/api/... (требует авторизации)")
    print("="*70)
    print("Логин по умолчанию: admin / admin")
    print("⚠️  ВНИМАНИЕ: Смените пароль администратора через меню пользователя!")
    print("="*70)
    print("🔍 Поиск работает по:")
    print("   - Именам компьютеров (кликабельно)")
    print("   - ФИО (без учета регистра)")
    print("   - ИНН")
    print("   - Названиям организаций")
    print("="*70)
    print("Нажмите Ctrl+C для остановки")
    print("="*70)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
