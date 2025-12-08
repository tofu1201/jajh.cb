import requests
import os
import json
import uuid
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory, make_response
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import secret_key, RUN_PORT, DATA_FILE, ban_ig, banword, log_webhook, approved_webhook, delete_request_webhook, blacklist_alert_webhook, admin_token

# 導入安全模組（新路徑）
from src.security.input_validator import (
    sanitize_html, validate_ig_username, validate_content, 
    validate_email, check_sql_injection, validate_password_strength
)
from src.security.security_monitor import get_security_monitor, logger
from src.security.password_hasher import verify_password

# 常數定義
MAX_ACCESS_LOG_ENTRIES = 5000
MAX_LOGIN_ATTEMPTS = 5
DEFAULT_LOGS_LIMIT = 200

app = Flask(__name__)
app.secret_key = secret_key

# Session 安全設定
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF token 不過期

# 初始化 CSRF 保護
csrf = CSRFProtect(app)

# 初始化 Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

BASE_URL = "https://jajhcb.qzz.io"
DELETE_REQUESTS_FILE = os.path.join('data', 'delete_requests.json')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ACCESS_LOG_FILE = os.path.join(BASE_DIR, 'logs', 'access_logs.json')

# 初始化安全監控
security_monitor = get_security_monitor(alert_webhook=blacklist_alert_webhook)

def load_delete_requests():
    try:
        with open(DELETE_REQUESTS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"requests": []}

def save_delete_requests(data):
    with open(DELETE_REQUESTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def load_access_logs():
    """讀取訪問日誌（回傳 list）。"""
    try:
        with open(ACCESS_LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    except Exception:
        return []


def append_access_log(entry, max_entries=MAX_ACCESS_LOG_ENTRIES):
    """將一筆訪問紀錄附加到 access_logs.json，保留最新 max_entries 筆。"""
    try:
        logs = load_access_logs()
        logs.append(entry)
        if len(logs) > max_entries:
            logs = logs[-max_entries:]
        with open(ACCESS_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        # 記錄錯誤但不影響主要流程
        import logging
        logging.error(f"append_access_log failed: {e}")


def get_client_ip():
    """從 request 中解析 client IP（支援反向代理標頭）。"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    else:
        return request.remote_addr


def check_and_block_ip(ip, threshold=MAX_LOGIN_ATTEMPTS):
    """檢查當天相同 IP 的登入失敗次數，若超過 threshold 則加入黑名單。

    回傳 True 若執行了封鎖（新加入黑名單），否則 False。
    """
    try:
        if not ip:
            return False
        # 讀取當前日誌，計算今天的失敗次數
        logs = load_access_logs()
        today = datetime.utcnow().date().isoformat()
        fail_events = ('admin_login', 'admin_token_login')
        count = 0
        for l in logs:
            ts = l.get('timestamp', '')
            if not ts.startswith(today):
                continue
            if l.get('event') in fail_events and l.get('result') == 'failure' and l.get('ip') == ip:
                count += 1

        # 當次數超過 threshold 就封鎖
        if count > threshold:
            blacklist = load_ip_blacklist()
            if ip not in blacklist:
                blacklist.append(ip)
                save_ip_blacklist(blacklist)
                # 記錄自動封鎖事件
                append_access_log({
                    'timestamp': datetime.utcnow().isoformat(),
                    'event': 'auto_block',
                    'result': 'blocked',
                    'ip': ip,
                    'user_agent': request.headers.get('User-Agent','')[:800],
                    'path': request.path,
                    'method': request.method,
                    'note': f'Auto-blocked after {count} failed admin login attempts today'
                })
                print(f"Auto-blocked IP {ip} after {count} failed attempts")
                return True
        return False
    except Exception as e:
        print(f"check_and_block_ip failed: {e}")
        return False

@app.route("/api/admin/update-delete-request", methods=["POST"])
def update_delete_request():
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    
    request_id = request.form.get("request_id")
    new_status = request.form.get("status")
    reject_reason = request.form.get("reject_reason", "")
    
    if not request_id or not new_status:
        return jsonify({"error": "Missing required fields"}), 400
        
    delete_requests = load_delete_requests()
    updated = False
    
    for req in delete_requests["requests"]:
        if req["id"] == request_id:
            req["status"] = new_status
            if new_status == "rejected":
                req["reject_reason"] = reject_reason
            updated = True
            break
    
    if updated:
        save_delete_requests(delete_requests)
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Request not found"}), 404




def load_submissions():
    """讀取投稿資料"""
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_submissions(data):
    """儲存投稿資料"""
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)
        
        
@app.after_request
def add_security_and_cache_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # 快取控制
    if request.path.startswith('/static/'):
        if any(request.path.endswith(ext) for ext in ['.webp', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf']):
            response.cache_control.max_age = 31536000
            response.cache_control.public = True
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        elif any(request.path.endswith(ext) for ext in ['.css', '.js']):
            response.cache_control.max_age = 86400
            response.cache_control.public = True
    elif request.path.endswith('.html') or request.path == '/':
        response.cache_control.no_cache = True
        response.cache_control.must_revalidate = True
    
    # 訪問日誌記錄
    try:
        if not request.path.startswith('/static/') and request.path not in ['/favicon.ico']:
            client_ip = get_client_ip()
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'ip': client_ip,
                'user_agent': request.headers.get('User-Agent', '')[:800],
                'path': request.path,
                'method': request.method,
                'query': request.query_string.decode() if request.query_string else '',
                'status': getattr(response, 'status_code', None)
            }
            append_access_log(entry)
    except Exception as e:
        import logging
        logging.error(f"access log write failed: {e}")

    return response

app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000 

# CSRF 錯誤處理
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """處理 CSRF 錯誤"""
    client_ip = get_client_ip()
    security_monitor.log_csrf_violation(
        ip=client_ip,
        path=request.path,
        user_agent=request.headers.get('User-Agent', '')
    )
    logger.warning(f"CSRF violation from {client_ip} on {request.path}")
    return render_template('500.html'), 400 

@app.route("/check-delete-request")
def view_delete_requests():
    request_id = request.args.get('request_id', '').strip()
    show_not_found = False
    request_info = None
    
    # 只有當用戶提供了請求ID時才進行查詢
    if request_id:
        delete_requests = load_delete_requests()
        for req in delete_requests.get("requests", []):
            if req["id"] == request_id:
                request_info = {
                    "id": req["id"],
                    "content": req.get("content", ""),
                    "date": req.get("date", ""),
                    "status": req.get("status", "pending"),
                    "reject_reason": req.get("reject_reason", "")
                }
                break
        show_not_found = not request_info
    
    return render_template("delete_requests.html", 
                         request_info=request_info,
                         show_not_found=show_not_found)

@app.route("/admin/delete-requests")
def admin_delete_requests():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    delete_requests = load_delete_requests()
    return render_template("delete_requests_admin.html", 
                         delete_requests=delete_requests["requests"])


@app.route('/adm/access-logs')
def admin_access_logs():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    logs = load_access_logs()
    # 支援簡單過濾
    ipq = request.args.get('ip', '').strip()
    pathq = request.args.get('path', '').strip()
    if ipq:
        logs = [l for l in logs if ipq in l.get('ip', '')]
    if pathq:
        logs = [l for l in logs if pathq in l.get('path', '')]
    # 顯示最新在前
    logs = list(reversed(logs))
    limit = 200
    try:
        limit = int(request.args.get('limit', DEFAULT_LOGS_LIMIT))
    except Exception:
        limit = DEFAULT_LOGS_LIMIT
    logs = logs[:limit]
    return render_template('admin_access_logs.html', logs=logs, username1=session.get('user'), ipq=ipq, pathq=pathq)

@app.route("/", methods=["GET", "POST"])
def submit():
    if request.method == "POST":
        logger.info(f"New submission from {get_client_ip()}")
        ig = request.form.get("ig", "").strip()
        content = request.form.get("content", "").strip()
        ip = request.form.get("ip_address", "").strip()

        # 輸入驗證
        # 1. 驗證 IG 使用者名稱
        if ig and not validate_ig_username(ig):
            status_message = "無效的 IG 使用者名稱格式"
            logger.warning(f"Invalid IG username: {ig} from {get_client_ip()}")
            return render_template("index.html", status_message=status_message)
        
        # 2. 驗證投稿內容
        is_valid, error_msg = validate_content(content)
        if not is_valid:
            logger.warning(f"Invalid content from {get_client_ip()}: {error_msg}")
            return render_template("index.html", status_message=error_msg)
        
        # 3. 檢查 SQL Injection
        if check_sql_injection(content) or check_sql_injection(ig):
            security_monitor.log_sql_injection_attempt(
                ip=get_client_ip(),
                input_data=content,
                field="content/ig"
            )
            status_message = "投稿時發生錯誤</br>主機回應: Error E-0099"
            return render_template("index.html", status_message=status_message)
        
        # 4. 清理輸入
        ig = sanitize_html(ig)
        content = sanitize_html(content)

        if not content:
            status_message = "投稿內容不能為空！"
            return render_template("index.html", status_message=status_message)
        if ig in ban_ig:
            status_message = "投稿時發生錯誤</br>主機回應: Error E-0019"
            return render_template("index.html", status_message=status_message)
        if any(word in content for word in banword):
            status_message = "投稿時發生錯誤</br>包含已被申請禁用的關鍵字"
            return render_template("index.html", status_message=status_message)

        submissions = load_submissions()
        submission_id = str(len(submissions) + 1).zfill(4)
        new_submission = {
            "id": submission_id,
            "ig": ig,
            "content": content,
            "followed": "None",
            "status": "pending",
            "timestamp": datetime.now().isoformat(),
        }
        
        submissions.append(new_submission)
        save_submissions(submissions)

        status_message = f"投稿成功！您的投稿編號是：{submission_id}"
        data = {
            "content": f"@everyone\n匿名仁愛新投稿通知\n投稿ID:{submission_id}\n投稿者IG:{ig}\n網絡識別資訊:{ip}\n內容:```{content}```",
            "username": "匿名仁愛投稿通知"
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(log_webhook, data=json.dumps(data), headers=headers)
        if response.status_code == 204:
            print("訊息發送成功！")
        else:
            print("訊息發送失敗，狀態碼：", response.status_code)
        return render_template("index.html", status_message=status_message)
    
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        client_ip = request.headers.get('X-Real-IP')
    else:
        client_ip = request.remote_addr
    
    with open(os.path.join('data', 'ipblacklist.json'),"r") as file:
        BLACKLIST = json.load(file)
    if client_ip in BLACKLIST:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        embed = {
            "embeds": [{
                "title": "🚫 黑名單 IP 訪問警報",
                "color": 15158332,
                "fields": [
                    {
                        "name": "IP 地址",
                        "value": f"`{client_ip}`",
                        "inline": True
                    },
                    {
                        "name": "時間",
                        "value": timestamp,
                        "inline": True
                    },
                    {
                        "name": "User Agent",
                        "value": user_agent[:100],
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "IP 黑名單監控系統｜匿名仁愛"
                },
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        try:
            if blacklist_alert_webhook:
                requests.post(blacklist_alert_webhook, json=embed, timeout=5)
        except Exception as e:
            import logging
            logging.error(f"Discord 通知發送失敗: {e}")
        
        return render_template('blocked.html', ip_address=client_ip), 403
    
    with open(os.path.join('data', 'ann.json'),"r") as file:
        ann = json.load(file)
    title = ann["title"]
    description = ann["description"]
    return render_template("index.html", status_message=None, ann_title=title, ann_description=description)

@app.route("/guest/delete")
def del_guest():
    return render_template("askfordelete.html")


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route("/adm/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def admin_login():
    """管理員登入頁面，加入 Rate Limiting 防止暴力破解"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        users_path = os.path.join(BASE_DIR, 'data', "users.json")
        try:
            with open(users_path,"r", encoding="utf-8") as file:
                data = json.load(file)
        except Exception:
            data = {}

        success = False
        if username in data:
            stored_password = data[username]
            # 支援兩種密碼格式：明文和 bcrypt 雜湊
            if stored_password.startswith('$2b$'):
                # bcrypt 雜湊密碼
                success = verify_password(password, stored_password)
            else:
                # 明文密碼（向後相容）
                success = (password == stored_password)

        # 記錄登入嘗試
        client_ip = get_client_ip()
        try:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'admin_login',
                'result': 'success' if success else 'failure',
                'username': username,
                'ip': client_ip,
                'user_agent': request.headers.get('User-Agent','')[:800],
                'path': request.path,
                'method': request.method,
                'query': request.query_string.decode() if request.query_string else ''
            }
            append_access_log(entry)
            
            # 記錄失敗登入到安全監控
            if not success:
                security_monitor.log_failed_login(
                    username=username,
                    ip=client_ip,
                    user_agent=request.headers.get('User-Agent', '')
                )
        except Exception as e:
            logger.error(f"log admin_login failed: {e}")

        if success:
            session["admin_logged_in"] = True
            session["user"] = username
            logger.info(f"Successful admin login: {username} from {client_ip}")
            return redirect(url_for("admin_panel"))
        else:
            logger.warning(f"Failed admin login attempt: {username} from {client_ip}")
    return render_template("admin_login.html")

from flask import send_from_directory, request

@app.route('/apple-touch-icon.png')
@app.route('/apple-touch-icon-<size>.png')
@app.route('/apple-touch-icon-<size>-precomposed.png')
def apple_touch_icon(size=None):
    return send_from_directory(app.static_folder, 'apple-touch-icon-180x180.png')



@app.route("/adm/dashboard", methods=["GET", "POST"])
def admin_panel():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    submissions = load_submissions()

    # 讀取 IP 黑名單以便在整合後台頁面顯示
    blacklist = load_ip_blacklist()

    if request.method == "POST":
        submission_id = request.form.get("submission_id", "").strip()
        new_status = request.form.get("status", "").strip()

        for submission in submissions:
            if submission["id"] == submission_id:
                submission["status"] = new_status
                save_submissions(submissions)
                flash(f"已更新投稿 ID {submission_id} 的狀態為 {new_status}！")
                co = submission["content"]
                if new_status == "approved":
                    data = {
                        "content": f"<@&1363366447048429588>新的投稿！\nID: {submission_id}\n```{co}```",
                        "username": "匿名仁愛"
                   }
                    headers = {
                        "Content-Type": "application/json"
                    }
                    if approved_webhook:
                        response = requests.post(approved_webhook, data=json.dumps(data), headers=headers)
            else:
                flash("找不到此投稿 ID！")

    return render_template("admin_panel.html", submissions=submissions, username1=session["user"], blacklist=blacklist)


def load_ip_blacklist():
    try:
        with open(os.path.join('data', 'ipblacklist.json'), "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except FileNotFoundError:
        return []


def save_ip_blacklist(data):
    with open(os.path.join('data', 'ipblacklist.json'), "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


@app.route("/adm/ip-blacklist", methods=["GET"])
def admin_ip_blacklist():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    blacklist = load_ip_blacklist()
    return render_template("admin_manage_ip.html", blacklist=blacklist, username1=session.get("user"))


@app.route("/adm/ip-blacklist/add", methods=["POST"])
def admin_ip_blacklist_add():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("請輸入 IP 地址！")
        return redirect(url_for("admin_ip_blacklist"))
    blacklist = load_ip_blacklist()
    if ip in blacklist:
        flash(f"{ip} 已在黑名單中。")
        return redirect(url_for("admin_ip_blacklist"))
    blacklist.append(ip)
    save_ip_blacklist(blacklist)
    flash(f"已新增封鎖 IP：{ip}")
    return redirect(url_for("admin_ip_blacklist"))


@app.route("/adm/ip-blacklist/remove", methods=["POST"])
def admin_ip_blacklist_remove():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("缺少要移除的 IP")
        return redirect(url_for("admin_ip_blacklist"))
    blacklist = load_ip_blacklist()
    if ip in blacklist:
        blacklist = [x for x in blacklist if x != ip]
        save_ip_blacklist(blacklist)
        flash(f"已移除封鎖 IP：{ip}")
    else:
        flash(f"{ip} 不在黑名單中。")
    return redirect(url_for("admin_ip_blacklist"))



@app.route("/api/edit", methods=["GET","POST"])
def edit():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    if request.method == "GET":  
        return render_template("editpost.html")
    if request.method == "POST":
        submission_id = request.form.get("submission_id", "").strip()
        new_content = request.form.get("content", "").strip()
        with open(os.path.join('data', 'submissions.json'), "r", encoding="utf-8") as file:
            data = json.load(file)
        for item in data:
            if item["id"] == submission_id:
                item["content"] = new_content
                with open(os.path.join('data', 'submissions.json'), "w", encoding="utf-8") as file:
                    json.dump(data, file, ensure_ascii=False, indent=4)        
                return redirect(f"/adm/dashboard#viewpost{submission_id}")
            else:
                flash("找不到此投稿 ID！")
               

    
@app.route("/api/edit/<sid>",methods=["GET"])
def edit_content(sid):    
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    submissions = load_submissions()
    for submission in submissions:
        if submission["id"] == sid:
            con = submission["content"]
    return render_template("editpost.html", content=con, soid=sid)

@app.route("/api/request-delete", methods=["POST"])
def api_askforedelete():
    email = request.form.get("email", "").strip()
    instagram = request.form.get("instagram", "").strip()
    content = request.form.get("article_content", "").strip()
    reason = request.form.get("delete_reason", "").strip()

    if not content or not reason:
        return jsonify({"success": False, "message": "請填寫必要欄位"}), 400

    request_id = str(uuid.uuid4())[:8].upper()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    delete_requests = load_delete_requests()
    new_request = {
        "id": request_id,
        "email": email,
        "instagram": instagram,
        "content": content,
        "reason": reason,
        "status": "pending",
        "date": current_time
    }
    
    if "requests" not in delete_requests:
        delete_requests["requests"] = []
    delete_requests["requests"].append(new_request)
    save_delete_requests(delete_requests)

    # Discord 通知
    try:
        discord_data = {
            "content": f"@everyone\n刪除請求通知\nID: `{request_id}`\n電子郵件: `{email}`\nIG: {instagram}\n要求刪除內容:```{content}```\n理由:```{reason}```",
            "username": "匿名仁愛刪除請求通知"
        }
        if delete_request_webhook:
            requests.post(delete_request_webhook, json=discord_data)
    except Exception as e:
        import logging
        logging.error(f"Discord 通知發送失敗: {str(e)}")

    # 設置 flash 消息並重定向到刪除請求頁面
    status_message = f"刪除請求已送出成功！您的請求編號是：{request_id}，請妥善保存此編號以便日後查詢進度。"
    return render_template("askfordelete.html", status_message=status_message)
    
    

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/api/v0/adm/user/get_content")
def app_get():
    with open(os.path.join('data', 'submissions.json'),"r") as file:
        data = json.load(file)
    return jsonify(data)

@app.route("/guidelines")
def guidelines():
    return render_template("guidelines.html")

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    """Generate sitemap including static routes and approved posts."""
    pages = []
    # Only include these public static pages in the sitemap (as requested)
    static_paths = ['/', '/support', '/guidelines', '/guest/delete']
    for p in static_paths:
        pages.append({'loc': f"{BASE_URL}{p}", 'changefreq': 'weekly', 'priority': '0.8'})

    # build xml
    sitemap_xml = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for p in pages:
        sitemap_xml.append('  <url>')
        sitemap_xml.append(f"    <loc>{p['loc']}</loc>")
        if p.get('lastmod'):
            sitemap_xml.append(f"    <lastmod>{p['lastmod']}</lastmod>")
        sitemap_xml.append(f"    <changefreq>{p['changefreq']}</changefreq>")
        sitemap_xml.append(f"    <priority>{p['priority']}</priority>")
        sitemap_xml.append('  </url>')
    sitemap_xml.append('</urlset>')

    response = make_response('\n'.join(sitemap_xml))
    response.headers['Content-Type'] = 'application/xml'
    return response



@app.route("/api/v9/admin/login/token/<token>/<user>")
@limiter.limit("5 per minute")
def admlogincode(token, user):
    """使用 Token 登入，加入 Rate Limiting"""
    if token == admin_token and user == "tofu1201":
        session["admin_logged_in"] = True
        session["user"] = user
        # 記錄 token 登入成功
        try:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'admin_token_login',
                'result': 'success',
                'username': user,
                'ip': get_client_ip(),
                'user_agent': request.headers.get('User-Agent','')[:800],
                'path': request.path,
                'method': request.method,
                'query': request.query_string.decode() if request.query_string else ''
            }
            append_access_log(entry)
        except Exception as e:
            print(f"log admlogincode success failed: {e}")
        return redirect(url_for("admin_panel"))
    else:
        # 記錄 token 登入失敗
        try:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'admin_token_login',
                'result': 'failure',
                'username': user,
                'ip': get_client_ip(),
                'user_agent': request.headers.get('User-Agent','')[:800],
                'path': request.path,
                'method': request.method,
                'query': request.query_string.decode() if request.query_string else ''
            }
            append_access_log(entry)
        except Exception as e:
            print(f"log admlogincode failure failed: {e}")
        return jsonify({"message": "Link expired"})
    
@app.route("/view/guest")
def view():
    submissions = load_submissions()
    return render_template("view.html",submissions=submissions)

@app.route("/api/v9/admin/acceptall")
def acceptall():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    submissions = load_submissions()
    for submission in submissions:
        if submission["status"] != "approved" and submission["status"] == "pending":
            submission["status"] = "approved"
            save_submissions(submissions)
            print(f"已更新投稿 狀態為 approved！")
            siddd = submission["id"]
            co = submission["content"]
            data = {
                "content": f"<@&1363366447048429588>新的投稿！\nID: {siddd}\n```{co}```",
                "username": "匿名仁愛"
           }
            headers = {
                "Content-Type": "application/json"
            }
            if approved_webhook:
                response = requests.post(approved_webhook, data=json.dumps(data), headers=headers)
    return redirect(url_for("admin_panel"))



@app.route("/adm/psdchange",methods=["POST"])
def editpassword():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    user = session.get("user")
    password = request.form.get("password", "").strip()
    with open(os.path.join('data', 'users.json'),"r") as file:
        data = json.load(file)
    data[user] = password
    with open(os.path.join('data', 'users.json'),"w") as file:
        json.dump(data,file)
    return redirect(url_for("admin_panel"))

@app.route("/test/<file>")
def test_html(file):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    return render_template(f"test_{file}.html")

@app.route("/admin/api/annedit", methods=["POST"])
def ann():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("content", "").strip()
        with open(os.path.join('data', 'ann.json'),"r") as file:
            data = json.load(file)
        data["title"] = title
        data["description"] = description
        with open(os.path.join('data', 'ann.json'),"w") as file:
            json.dump(data,file)
        return redirect(url_for("admin_panel"))
        
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    print("--------------------------------------------------------------------------")
    print(f"""
  ╔╗╔═══╗  ╔╗╔╗ ╔╗    ╔═══╗╔══╗ 
  ║║║╔═╗║  ║║║║ ║║    ║╔═╗║║╔╗║ 
  ║║║║ ║║  ║║║╚═╝║    ║║ ╚╝║╚╝╚╗
╔╗║║║╚═╝║╔╗║║║╔═╗║    ║║ ╔╗║╔═╗║
║╚╝║║╔═╗║║╚╝║║║ ║║    ║╚═╝║║╚═╝║
╚══╝╚╝ ╚╝╚══╝╚╝ ╚╝    ╚═══╝╚═══╝
            端口:{RUN_PORT}
            總用戶數:2
        版本號: V3.9｜系統優化版
        授權: 好吃豆腐數位永久授權
 """)
    print("--------------------------------------------------------------------------")
    print("✅匿名仁愛網站啟動成功")
    print("--------------------------------------------------------------------------")
    app.run(host="0.0.0.0", port=RUN_PORT, debug=True)