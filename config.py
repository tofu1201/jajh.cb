from dotenv import load_dotenv
import os

# 載入 .env 檔案
load_dotenv()

# Flask 配置
secret_key = os.getenv('SECRET_KEY', 'tP9#xV2!qL7@mF4^Zs8&nH1$wR5*eJ0_Kc3+Bd6%gT9=Yr2!uQ7@vM4^pS8&kN1$hA5*fD0')
RUN_PORT = int(os.getenv('RUN_PORT', 25612))
DATA_FILE = os.path.join('data', os.getenv('DATA_FILE', 'submissions.json'))

# 黑名單設定
ban_ig = []
banword = []

# Discord Webhooks（從環境變數讀取）
log_webhook = os.getenv('DISCORD_LOG_WEBHOOK', '')
approved_webhook = os.getenv('DISCORD_APPROVED_WEBHOOK', '')
delete_request_webhook = os.getenv('DISCORD_DELETE_REQUEST_WEBHOOK', '')
blacklist_alert_webhook = os.getenv('DISCORD_BLACKLIST_ALERT_WEBHOOK', '')

# 管理員 Token
admin_token = os.getenv('ADMIN_TOKEN', '')