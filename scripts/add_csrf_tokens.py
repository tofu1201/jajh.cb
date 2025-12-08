#!/usr/bin/env python3
"""
批量添加 CSRF Token 到模板檔案的腳本
"""
import os
import re

TEMPLATES_DIR = "templates"

# 需要添加 CSRF token 的模板檔案
TEMPLATES_TO_UPDATE = [
    "askfordelete.html",
    "editpost.html",
    "admin_panel.html",
    "admin_manage_ip.html",
    "superadmin.html"
]

def add_csrf_token_to_form(content):
    """在表單開頭添加 CSRF token"""
    # 匹配 <form...> 標籤後添加 CSRF token
    pattern = r'(<form[^>]*method=["\']POST["\'][^>]*>)'
    
    def replacement(match):
        form_tag = match.group(1)
        # 檢查是否已經有 csrf_token
        if 'csrf_token' in content[match.start():match.end()+200]:
            return form_tag
        return form_tag + '\n        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>'
    
    return re.sub(pattern, replacement, content, flags=re.IGNORECASE)

def main():
    updated_count = 0
    
    for template_file in TEMPLATES_TO_UPDATE:
        file_path = os.path.join(TEMPLATES_DIR, template_file)
        
        if not os.path.exists(file_path):
            print(f"⚠️  檔案不存在: {file_path}")
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 檢查是否包含 POST 表單
            if 'method="POST"' not in content and 'method="post"' not in content:
                print(f"ℹ️  跳過 {template_file} (沒有 POST 表單)")
                continue
            
            # 檢查是否已經有 csrf_token
            if 'csrf_token()' in content:
                print(f"✓  {template_file} 已包含 CSRF token")
                continue
            
            # 添加 CSRF token
            updated_content = add_csrf_token_to_form(content)
            
            # 寫回檔案
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            print(f"✓  已更新 {template_file}")
            updated_count += 1
            
        except Exception as e:
            print(f"❌ 處理 {template_file} 時發生錯誤: {e}")
    
    print(f"\n完成！共更新 {updated_count} 個檔案")

if __name__ == "__main__":
    main()
