# 進階安全功能使用指南

## 1. 密碼雜湊（bcrypt）

### 遷移現有密碼

```bash
# 將所有明文密碼遷移到 bcrypt 雜湊
python3 password_hasher.py migrate
```

這會：
- 自動備份原始 `users.json` 到 `users.json.backup`
- 將所有明文密碼轉換為 bcrypt 雜湊
- 保留已經是雜湊格式的密碼

### 建立新使用者

```bash
# 建立新使用者（自動使用 bcrypt）
python3 password_hasher.py create <username> <password>
```

### 測試密碼驗證

```bash
# 測試密碼是否匹配雜湊
python3 password_hasher.py test <password> <hash>
```

### 向後相容性

`app.py` 現在支援兩種密碼格式：
- **bcrypt 雜湊**：以 `$2b$` 開頭的密碼會使用 bcrypt 驗證
- **明文密碼**：其他密碼會使用直接比對（向後相容）

這意味著您可以：
1. 逐步遷移密碼（不需要一次全部遷移）
2. 新舊密碼格式可以共存
3. 遷移後系統仍然正常運作

---

## 2. 輸入驗證與清理

### 自動驗證

所有投稿現在會自動進行以下驗證：

1. **IG 使用者名稱驗證**
   - 格式：1-30 個字符
   - 只允許字母、數字、底線和點

2. **內容驗證**
   - 最小長度：10 個字符
   - 最大長度：5000 個字符
   - 檢查過多重複字符

3. **SQL Injection 檢測**
   - 自動檢測常見的 SQL 注入模式
   - 觸發時記錄到安全日誌並發送警報

4. **HTML 清理**
   - 自動轉義 HTML 特殊字符
   - 防止 XSS 攻擊

### 可用的驗證函數

在 `input_validator.py` 中提供：

```python
from input_validator import (
    sanitize_html,           # HTML 清理
    validate_ig_username,    # IG 使用者名稱驗證
    validate_content,        # 內容驗證
    validate_email,          # 電子郵件驗證
    validate_ip_address,     # IP 地址驗證
    check_sql_injection,     # SQL Injection 檢測
    validate_password_strength  # 密碼強度驗證
)
```

---

## 3. 日誌監控與警報系統

### 日誌檔案

系統會自動建立以下日誌：

- `logs/app.log` - 一般應用程式日誌
- `logs/security.log` - 安全事件日誌

### 自動警報

以下事件會觸發 Discord 警報：

| 事件類型 | 觸發條件 | 嚴重程度 |
|---------|---------|---------|
| 失敗登入 | 5 次失敗 | WARNING |
| CSRF 違規 | 3 次違規 | ERROR |
| 速率限制 | 10 次超過 | WARNING |
| SQL Injection | 1 次嘗試 | CRITICAL |

### 手動記錄安全事件

```python
from security_monitor import get_security_monitor

security_monitor = get_security_monitor()

# 記錄可疑活動
security_monitor.log_suspicious_activity(
    'unusual_pattern',
    {'ip': '1.2.3.4', 'details': '...'}
)
```

### 查看日誌

```bash
# 查看最新的安全日誌
tail -f logs/security.log

# 查看應用程式日誌
tail -f logs/app.log

# 搜尋特定 IP 的活動
grep "1.2.3.4" logs/security.log
```

---

## 安全事件範例

### CSRF 違規
```json
{
  "timestamp": "2025-12-09T00:00:00",
  "event_type": "csrf_violation",
  "severity": "ERROR",
  "details": {
    "ip": "1.2.3.4",
    "path": "/",
    "user_agent": "Mozilla/5.0..."
  }
}
```

### SQL Injection 嘗試
```json
{
  "timestamp": "2025-12-09T00:00:00",
  "event_type": "sql_injection",
  "severity": "CRITICAL",
  "details": {
    "ip": "1.2.3.4",
    "field": "content",
    "input_data": "SELECT * FROM..."
  }
}
```

### 失敗登入
```json
{
  "timestamp": "2025-12-09T00:00:00",
  "event_type": "failed_login",
  "severity": "WARNING",
  "details": {
    "username": "admin",
    "ip": "1.2.3.4",
    "user_agent": "Mozilla/5.0..."
  }
}
```

---

## 最佳實踐

### 1. 定期檢查日誌
```bash
# 設定 cron job 每天檢查安全日誌
0 9 * * * tail -100 /path/to/logs/security.log | mail -s "Security Log" admin@example.com
```

### 2. 監控警報
- 確保 Discord webhook 正常運作
- 定期檢查 Discord 頻道的警報訊息

### 3. 密碼政策
- 建議所有管理員密碼遷移到 bcrypt
- 定期更換管理員密碼
- 使用強密碼（至少 8 個字符，包含字母和數字）

### 4. 日誌輪替
```bash
# 建立日誌輪替配置 /etc/logrotate.d/anonymous-app
/path/to/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
}
```

---

## 疑難排解

### 問題：密碼遷移後無法登入

**解決方案**：
1. 檢查 `users.json.backup` 確認原始密碼
2. 使用備份還原：`cp users.json.backup users.json`
3. 重新執行遷移：`python3 password_hasher.py migrate`

### 問題：日誌檔案過大

**解決方案**：
```bash
# 手動清理舊日誌
find logs/ -name "*.log" -mtime +30 -delete

# 或使用日誌輪替（見上方）
```

### 問題：警報未發送

**解決方案**：
1. 檢查 `.env` 中的 `DISCORD_BLACKLIST_ALERT_WEBHOOK`
2. 測試 webhook：
   ```bash
   curl -X POST <webhook_url> \
     -H "Content-Type: application/json" \
     -d '{"content": "Test message"}'
   ```
3. 檢查 `logs/app.log` 中的錯誤訊息
