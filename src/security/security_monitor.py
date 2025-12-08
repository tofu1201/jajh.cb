"""
日誌監控與警報系統
提供結構化日誌記錄和異常警報功能
"""
import logging
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any
import requests

# 日誌配置
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")
SECURITY_LOG_FILE = os.path.join(LOG_DIR, "security.log")

# 確保日誌目錄存在
os.makedirs(LOG_DIR, exist_ok=True)

# 配置主日誌記錄器
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('匿名仁愛')

# 配置安全日誌記錄器
security_logger = logging.getLogger('安全監控')
security_handler = logging.FileHandler(SECURITY_LOG_FILE, encoding='utf-8')
security_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

class SecurityMonitor:
    """安全監控類別"""
    
    def __init__(self, alert_webhook: Optional[str] = None):
        """
        初始化安全監控
        
        Args:
            alert_webhook: Discord webhook URL 用於發送警報
        """
        self.alert_webhook = alert_webhook
        self.alert_threshold = {
            'failed_login': 5,  # 5 次失敗登入
            'csrf_violation': 3,  # 3 次 CSRF 違規
            'rate_limit': 10,  # 10 次速率限制
            'sql_injection': 1,  # 1 次 SQL Injection 嘗試
        }
        self.alert_count = {}
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = 'WARNING'):
        """
        記錄安全事件
        
        Args:
            event_type: 事件類型
            details: 事件詳情
            severity: 嚴重程度 (INFO, WARNING, ERROR, CRITICAL)
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details
        }
        
        # 記錄到安全日誌
        log_message = json.dumps(log_entry, ensure_ascii=False)
        
        if severity == 'CRITICAL':
            security_logger.critical(log_message)
        elif severity == 'ERROR':
            security_logger.error(log_message)
        elif severity == 'WARNING':
            security_logger.warning(log_message)
        else:
            security_logger.info(log_message)
        
        # 檢查是否需要發送警報
        self._check_alert(event_type, details)
    
    def _check_alert(self, event_type: str, details: Dict[str, Any]):
        """
        檢查是否需要發送警報
        
        Args:
            event_type: 事件類型
            details: 事件詳情
        """
        # 計數特定事件
        if event_type not in self.alert_count:
            self.alert_count[event_type] = 0
        
        self.alert_count[event_type] += 1
        
        # 檢查是否超過閾值
        threshold = self.alert_threshold.get(event_type, float('inf'))
        if self.alert_count[event_type] >= threshold:
            self._send_alert(event_type, details)
            # 重置計數
            self.alert_count[event_type] = 0
    
    def _send_alert(self, event_type: str, details: Dict[str, Any]):
        """
        發送警報到 Discord
        
        Args:
            event_type: 事件類型
            details: 事件詳情
        """
        if not self.alert_webhook:
            return
        
        # 建立警報訊息
        embed = {
            "embeds": [{
                "title": f"🚨 安全警報：{event_type}",
                "color": 15158332,  # 紅色
                "fields": [
                    {
                        "name": "事件類型",
                        "value": event_type,
                        "inline": True
                    },
                    {
                        "name": "時間",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "inline": True
                    }
                ],
                "description": f"```json\n{json.dumps(details, ensure_ascii=False, indent=2)}\n```",
                "footer": {
                    "text": "匿名仁愛安全監控系統"
                },
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        try:
            response = requests.post(self.alert_webhook, json=embed, timeout=5)
            if response.status_code == 204:
                logger.info(f"安全警報已發送：{event_type}")
            else:
                logger.error(f"安全警報發送失敗：{response.status_code}")
        except Exception as e:
            logger.error(f"發送安全警報時發生錯誤：{e}")
    
    def log_failed_login(self, username: str, ip: str, user_agent: str):
        """記錄失敗的登入嘗試"""
        self.log_security_event(
            'failed_login',
            {
                'username': username,
                'ip': ip,
                'user_agent': user_agent
            },
            'WARNING'
        )
    
    def log_csrf_violation(self, ip: str, path: str, user_agent: str):
        """記錄 CSRF 違規"""
        self.log_security_event(
            'csrf_violation',
            {
                'ip': ip,
                'path': path,
                'user_agent': user_agent
            },
            'ERROR'
        )
    
    def log_rate_limit_exceeded(self, ip: str, endpoint: str):
        """記錄速率限制超過"""
        self.log_security_event(
            'rate_limit',
            {
                'ip': ip,
                'endpoint': endpoint
            },
            'WARNING'
        )
    
    def log_sql_injection_attempt(self, ip: str, input_data: str, field: str):
        """記錄 SQL Injection 嘗試"""
        self.log_security_event(
            'sql_injection',
            {
                'ip': ip,
                'field': field,
                'input_data': input_data[:200]  # 只記錄前 200 個字符
            },
            'CRITICAL'
        )
    
    def log_suspicious_activity(self, activity_type: str, details: Dict[str, Any]):
        """記錄可疑活動"""
        self.log_security_event(
            'suspicious_activity',
            {
                'activity_type': activity_type,
                **details
            },
            'WARNING'
        )

def get_security_monitor(alert_webhook: Optional[str] = None) -> SecurityMonitor:
    """
    獲取安全監控實例（單例模式）
    
    Args:
        alert_webhook: Discord webhook URL
        
    Returns:
        SecurityMonitor 實例
    """
    if not hasattr(get_security_monitor, '_instance'):
        get_security_monitor._instance = SecurityMonitor(alert_webhook)
    return get_security_monitor._instance
