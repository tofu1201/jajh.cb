"""
輸入驗證與清理工具模組
提供各種輸入驗證和清理函數，防止 XSS、SQL Injection 等攻擊
"""
import re
import html
from typing import Optional

def sanitize_html(text: str) -> str:
    """
    清理 HTML 標籤，防止 XSS 攻擊
    
    Args:
        text: 要清理的文字
        
    Returns:
        清理後的文字
    """
    if not text:
        return ""
    # 轉義 HTML 特殊字符
    return html.escape(text.strip())

def validate_ig_username(username: str) -> bool:
    """
    驗證 Instagram 使用者名稱格式
    
    Args:
        username: IG 使用者名稱
        
    Returns:
        是否有效
    """
    if not username:
        return True  # 選填欄位
    
    # IG 使用者名稱規則：1-30 個字符，只能包含字母、數字、底線和點
    pattern = r'^[a-zA-Z0-9._]{1,30}$'
    return bool(re.match(pattern, username))

def validate_content(content: str, min_length: int = 10, max_length: int = 5000) -> tuple[bool, str]:
    """
    驗證投稿內容
    
    Args:
        content: 投稿內容
        min_length: 最小長度
        max_length: 最大長度
        
    Returns:
        (是否有效, 錯誤訊息)
    """
    if not content or not content.strip():
        return False, "投稿內容不能為空"
    
    content = content.strip()
    
    if len(content) < min_length:
        return False, f"投稿內容至少需要 {min_length} 個字符"
    
    if len(content) > max_length:
        return False, f"投稿內容不能超過 {max_length} 個字符"
    
    # 檢查是否包含過多重複字符（可能是垃圾訊息）
    if re.search(r'(.)\1{50,}', content):
        return False, "投稿內容包含過多重複字符"
    
    return True, ""

def validate_email(email: str) -> bool:
    """
    驗證電子郵件格式
    
    Args:
        email: 電子郵件地址
        
    Returns:
        是否有效
    """
    if not email:
        return True  # 選填欄位
    
    # 基本的電子郵件格式驗證
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email)) and len(email) <= 254

def sanitize_filename(filename: str) -> str:
    """
    清理檔案名稱，防止路徑遍歷攻擊
    
    Args:
        filename: 原始檔案名稱
        
    Returns:
        安全的檔案名稱
    """
    # 移除路徑分隔符和特殊字符
    filename = re.sub(r'[^\w\s.-]', '', filename)
    # 移除開頭的點（隱藏檔案）
    filename = filename.lstrip('.')
    # 限制長度
    return filename[:255]

def validate_ip_address(ip: str) -> bool:
    """
    驗證 IP 地址格式（IPv4）
    
    Args:
        ip: IP 地址
        
    Returns:
        是否有效
    """
    if not ip:
        return False
    
    # IPv4 格式驗證
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    # 檢查每個數字是否在 0-255 範圍內
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def sanitize_url(url: str) -> Optional[str]:
    """
    驗證並清理 URL
    
    Args:
        url: URL 字串
        
    Returns:
        清理後的 URL，如果無效則返回 None
    """
    if not url:
        return None
    
    # 只允許 http 和 https 協議
    if not url.startswith(('http://', 'https://')):
        return None
    
    # 基本 URL 格式驗證
    pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
    if re.match(pattern, url):
        return url
    
    return None

def check_sql_injection(text: str) -> bool:
    """
    檢查文字是否包含常見的 SQL Injection 模式
    
    Args:
        text: 要檢查的文字
        
    Returns:
        是否可疑
    """
    if not text:
        return False
    
    # 常見的 SQL Injection 關鍵字
    sql_keywords = [
        r'\bSELECT\b.*\bFROM\b',
        r'\bINSERT\b.*\bINTO\b',
        r'\bUPDATE\b.*\bSET\b',
        r'\bDELETE\b.*\bFROM\b',
        r'\bDROP\b.*\bTABLE\b',
        r'\bUNION\b.*\bSELECT\b',
        r'--',
        r'/\*.*\*/',
        r'\bOR\b.*=.*',
        r'\bAND\b.*=.*',
    ]
    
    text_upper = text.upper()
    return any(re.search(pattern, text_upper, re.IGNORECASE) for pattern in sql_keywords)

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    驗證密碼強度
    
    Args:
        password: 密碼
        
    Returns:
        (是否有效, 錯誤訊息)
    """
    if not password:
        return False, "密碼不能為空"
    
    if len(password) < 8:
        return False, "密碼長度至少需要 8 個字符"
    
    if len(password) > 128:
        return False, "密碼長度不能超過 128 個字符"
    
    # 檢查是否包含至少一個數字
    if not re.search(r'\d', password):
        return False, "密碼必須包含至少一個數字"
    
    # 檢查是否包含至少一個字母
    if not re.search(r'[a-zA-Z]', password):
        return False, "密碼必須包含至少一個字母"
    
    return True, ""
