"""
密碼雜湊遷移工具
用於將現有明文密碼遷移到 bcrypt 雜湊格式
"""
import json
import bcrypt
from typing import Dict

def hash_password(password: str) -> str:
    """
    使用 bcrypt 雜湊密碼
    
    Args:
        password: 明文密碼
        
    Returns:
        雜湊後的密碼
    """
    # 生成 salt 並雜湊密碼
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    驗證密碼
    
    Args:
        password: 明文密碼
        hashed: 雜湊後的密碼
        
    Returns:
        是否匹配
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def migrate_passwords(users_file: str = 'users.json', backup: bool = True):
    """
    遷移 users.json 中的所有密碼到 bcrypt 格式
    
    Args:
        users_file: 使用者檔案路徑
        backup: 是否備份原始檔案
    """
    print("=" * 60)
    print("  密碼雜湊遷移工具")
    print("=" * 60)
    print()
    
    # 讀取現有使用者資料
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except FileNotFoundError:
        print(f"❌ 找不到檔案：{users_file}")
        return
    except json.JSONDecodeError:
        print(f"❌ 檔案格式錯誤：{users_file}")
        return
    
    if not users:
        print("⚠️  沒有使用者需要遷移")
        return
    
    print(f"找到 {len(users)} 個使用者帳號")
    print()
    
    # 備份原始檔案
    if backup:
        backup_file = f"{users_file}.backup"
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        print(f"✓ 已備份原始檔案到：{backup_file}")
    
    # 遷移密碼
    migrated_users = {}
    for username, password in users.items():
        # 檢查是否已經是 bcrypt 雜湊（以 $2b$ 開頭）
        if password.startswith('$2b$'):
            print(f"⊙ {username}: 已經是雜湊格式，跳過")
            migrated_users[username] = password
        else:
            # 雜湊密碼
            hashed = hash_password(password)
            migrated_users[username] = hashed
            print(f"✓ {username}: 已雜湊密碼")
    
    # 儲存遷移後的資料
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(migrated_users, f, ensure_ascii=False, indent=2)
    
    print()
    print("=" * 60)
    print(f"✓ 密碼遷移完成！共處理 {len(migrated_users)} 個帳號")
    print("=" * 60)
    print()
    print("⚠️  重要提醒：")
    print("1. 請更新 app.py 中的登入邏輯以使用 bcrypt 驗證")
    print("2. 原始密碼已無法還原，請妥善保管備份檔案")
    print("3. 建議測試登入功能確保一切正常")
    print()

def create_new_user(username: str, password: str, users_file: str = 'users.json'):
    """
    建立新使用者（使用 bcrypt 雜湊）
    
    Args:
        username: 使用者名稱
        password: 密碼
        users_file: 使用者檔案路徑
    """
    # 讀取現有使用者
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}
    
    # 檢查使用者是否已存在
    if username in users:
        print(f"❌ 使用者 {username} 已存在")
        return False
    
    # 雜湊密碼並儲存
    hashed = hash_password(password)
    users[username] = hashed
    
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    
    print(f"✓ 已建立使用者：{username}")
    return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "migrate":
            # 遷移現有密碼
            migrate_passwords()
        
        elif command == "create" and len(sys.argv) == 4:
            # 建立新使用者
            username = sys.argv[2]
            password = sys.argv[3]
            create_new_user(username, password)
        
        elif command == "test" and len(sys.argv) == 4:
            # 測試密碼驗證
            password = sys.argv[2]
            hashed = sys.argv[3]
            result = verify_password(password, hashed)
            print(f"密碼驗證結果：{'✓ 匹配' if result else '✗ 不匹配'}")
        
        else:
            print("用法：")
            print("  python3 password_hasher.py migrate              # 遷移現有密碼")
            print("  python3 password_hasher.py create <user> <pwd>  # 建立新使用者")
            print("  python3 password_hasher.py test <pwd> <hash>    # 測試密碼驗證")
    else:
        print("用法：")
        print("  python3 password_hasher.py migrate              # 遷移現有密碼")
        print("  python3 password_hasher.py create <user> <pwd>  # 建立新使用者")
        print("  python3 password_hasher.py test <pwd> <hash>    # 測試密碼驗證")
