#!/bin/bash

# 匿名仁愛系統 - 安全優化部署腳本

echo "=========================================="
echo "  匿名仁愛系統 - 安全優化部署"
echo "=========================================="
echo ""

# 檢查 Python 版本
echo "檢查 Python 環境..."
python3 --version || { echo "❌ 需要 Python 3"; exit 1; }

# 安裝依賴套件
echo ""
echo "安裝依賴套件..."
pip3 install -r requirements.txt || { echo "❌ 套件安裝失敗"; exit 1; }

# 檢查 .env 檔案
echo ""
if [ ! -f ".env" ]; then
    echo "⚠️  未找到 .env 檔案"
    echo "正在從 .env.example 建立 .env..."
    cp .env.example .env
    echo "✓  已建立 .env 檔案"
    echo ""
    echo "⚠️  重要：請編輯 .env 檔案並填入正確的配置值！"
    echo "   - SECRET_KEY: 請更換為隨機字串"
    echo "   - DISCORD_*_WEBHOOK: 填入您的 Discord Webhook URLs"
    echo "   - ADMIN_TOKEN: 請更換為隨機字串"
    echo ""
    read -p "按 Enter 繼續..."
else
    echo "✓  找到 .env 檔案"
fi

# 添加 CSRF tokens 到模板
echo ""
echo "添加 CSRF 保護到模板..."
python3 add_csrf_tokens.py || echo "⚠️  CSRF token 添加腳本執行失敗（可能已經添加過）"

# 檢查必要的 JSON 檔案
echo ""
echo "檢查資料檔案..."
for file in submissions.json users.json ipblacklist.json delete_requests.json ann.json access_logs.json; do
    if [ ! -f "$file" ]; then
        echo "⚠️  $file 不存在，正在建立..."
        case $file in
            submissions.json|access_logs.json)
                echo "[]" > $file
                ;;
            delete_requests.json)
                echo '{"requests": []}' > $file
                ;;
            ipblacklist.json)
                echo "[]" > $file
                ;;
            users.json)
                echo "{}" > $file
                ;;
            ann.json)
                echo '{"title": "", "description": ""}' > $file
                ;;
        esac
        echo "✓  已建立 $file"
    fi
done

echo ""
echo "=========================================="
echo "  部署完成！"
echo "=========================================="
echo ""
echo "下一步："
echo "1. 編輯 .env 檔案，填入正確的配置"
echo "2. 執行 python3 app.py 啟動應用程式"
echo "3. 檢查 http://localhost:25612 確認運作正常"
echo ""
echo "安全性改善："
echo "✓ CSRF 保護已啟用"
echo "✓ Rate Limiting 已啟用（登入端點）"
echo "✓ HTTP 安全標頭已添加"
echo "✓ Session 安全性已加強"
echo "✓ 敏感資訊已移至環境變數"
echo "✓ 錯誤處理已改善"
echo ""
