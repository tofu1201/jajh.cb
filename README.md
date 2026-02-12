# 匿名仁愛系統

一個安全、現代化的匿名投稿系統，使用 Flask 框架開發。

## 功能特色

- ✅ 匿名投稿功能
- ✅ 管理員後台系統
- ✅ IP 黑名單管理
- ✅ Discord 通知整合
- ✅ CSRF 保護
- ✅ Rate Limiting
- ✅ 密碼雜湊（bcrypt）
- ✅ 輸入驗證與清理
- ✅ 安全監控與警報

## 快速開始

### 1. 安裝依賴

```bash
pip3 install -r requirements.txt
```

### 2. 配置環境變數

複製 `.env.example` 到 `.env` 並填入您的配置：

```bash
cp .env.example .env
# 編輯 .env 檔案
```

### 3. 啟動應用程式

```bash
python3 app.py
```

應用程式將在 `http://localhost:25612` 啟動。

## 專案結構

```
├── app.py                  # 主應用程式
├── config.py               # 配置檔案
├── requirements.txt        # 依賴清單
├── src/                    # 原始碼
│   └── security/           # 安全模組
├── data/                   # 資料檔案
├── logs/                   # 日誌檔案
├── scripts/                # 工具腳本
├── docs/                   # 文檔
├── static/                 # 靜態資源
└── templates/              # HTML 模板
```

## 文檔

- [安全功能說明](docs/README_SECURITY.md)
- [進階安全功能](docs/ADVANCED_SECURITY.md)

## 工具腳本

```bash
# 自動化部署
./scripts/setup.sh

# 密碼遷移到 bcrypt
python3 src/security/password_hasher.py migrate

# 添加 CSRF tokens
python3 scripts/add_csrf_tokens.py
```

## 安全性

本系統實作了多層次的安全防護：

- **CSRF 保護**：所有 POST 請求需要 CSRF token
- **Rate Limiting**：防止暴力破解攻擊
- **輸入驗證**：自動檢測 SQL Injection 和 XSS
- **密碼雜湊**：使用 bcrypt 加密密碼
- **安全監控**：自動記錄並警報可疑活動

## 授權

Copyright © 2025 好吃豆腐數位工作室
