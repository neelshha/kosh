#!/usr/bin/env python3
"""
Test script to verify the refactored admin dashboard works correctly.
This will simulate logging in as admin and check if all resources load properly.
"""

import requests
import json

# Test URLs
BASE_URL = "http://127.0.0.1:7130"
LOGIN_URL = f"{BASE_URL}/login"
ADMIN_URL = f"{BASE_URL}/admin"

def test_admin_login_and_dashboard():
    """Test admin login and dashboard access"""
    session = requests.Session()
    
    print("🔐 Testing admin login...")
    
    # Login as admin
    login_data = {
        'user_id': 'admin',
        'password': 'pass'
    }
    
    response = session.post(LOGIN_URL, data=login_data, allow_redirects=False)
    print(f"Login response status: {response.status_code}")
    
    if response.status_code == 302:
        print("✅ Login successful (redirect response)")
        
        # Access admin dashboard
        print("🔧 Testing admin dashboard access...")
        dashboard_response = session.get(ADMIN_URL)
        print(f"Dashboard response status: {dashboard_response.status_code}")
        
        if dashboard_response.status_code == 200:
            print("✅ Admin dashboard accessible")
            
            # Check if all our refactored files are being loaded
            content = dashboard_response.text
            
            # Check for our CSS file
            if '/static/css/admin.css' in content:
                print("✅ CSS file referenced correctly")
            else:
                print("❌ CSS file not found in HTML")
                
            # Check for our JS files
            js_files = [
                '/static/js/config/tailwind.config.js',
                '/static/js/components/modal.js',
                '/static/js/components/toast.js',
                '/static/js/utils/ui-helpers.js',
                '/static/js/utils/admin-links.js',
                '/static/js/modules/user-manager.js',
                '/static/js/modules/policy-manager.js',
                '/static/js/modules/attribute-manager.js',
                '/static/js/modules/audit-manager.js',
                '/static/js/modules/file-manager.js',
                '/static/js/modules/realtime-manager.js',
                '/static/js/admin-dashboard.js'
            ]
            
            missing_files = []
            for js_file in js_files:
                if js_file in content:
                    print(f"✅ {js_file} referenced correctly")
                else:
                    missing_files.append(js_file)
                    print(f"❌ {js_file} not found in HTML")
            
            if not missing_files:
                print("🎉 All refactored files are properly referenced!")
            else:
                print(f"⚠️  Missing references: {missing_files}")
                
            # Test if each static file actually exists by making requests
            print("\n🔍 Testing static file availability...")
            for js_file in js_files:
                file_response = session.get(f"{BASE_URL}{js_file}")
                if file_response.status_code == 200:
                    print(f"✅ {js_file} loads successfully")
                else:
                    print(f"❌ {js_file} failed to load (status: {file_response.status_code})")
            
            # Test CSS file
            css_response = session.get(f"{BASE_URL}/static/css/admin.css")
            if css_response.status_code == 200:
                print("✅ /static/css/admin.css loads successfully")
            else:
                print(f"❌ CSS file failed to load (status: {css_response.status_code})")
                
        else:
            print(f"❌ Failed to access admin dashboard (status: {dashboard_response.status_code})")
    else:
        print(f"❌ Login failed (status: {response.status_code})")

if __name__ == "__main__":
    print("🧪 Testing refactored admin dashboard...")
    print("=" * 50)
    
    try:
        test_admin_login_and_dashboard()
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the server. Make sure it's running on http://127.0.0.1:7130")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        
    print("=" * 50)
    print("🏁 Test completed!")
