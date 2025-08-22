#!/usr/bin/env python3
"""
Enhanced API test script for VirusJaeger
Tests all the major endpoints including authentication
"""
import requests
import time
import json
import sys
import tempfile
import os

API_BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8000'
API_KEY = 'demo-api-key'

def test_endpoint(name, url, method='GET', headers=None, files=None, data=None, params=None):
    """Test an API endpoint"""
    print(f"\n🧪 Testing {name}...")
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params)
        elif method == 'POST':
            response = requests.post(url, headers=headers, files=files, data=data, params=params)
        
        print(f"   Status: {response.status_code}")
        if response.status_code < 400:
            result = response.json()
            print(f"   ✅ Success: {json.dumps(result, indent=2)[:200]}...")
            return result
        else:
            print(f"   ❌ Error: {response.text}")
            return None
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        return None

def main():
    print("🚀 Testing Enhanced VirusJaeger API")
    print(f"   Base URL: {API_BASE}")
    
    # Test health endpoint
    test_endpoint("Health Check", f"{API_BASE}/health")
    
    # Test API info
    api_info = test_endpoint("API Info", f"{API_BASE}/api-info")
    
    # Test statistics
    test_endpoint("Statistics", f"{API_BASE}/statistics")
    
    # Test file upload
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is a test file for the enhanced API")
        test_file = f.name
    
    try:
        with open(test_file, 'rb') as f:
            files = {'file': ('test_enhanced.txt', f, 'text/plain')}
            upload_result = test_endpoint(
                "File Upload", 
                f"{API_BASE}/files", 
                method='POST', 
                files=files
            )
        
        if upload_result and 'sha256' in upload_result:
            sha256 = upload_result['sha256']
            
            # Wait for scan to complete
            print("   ⏳ Waiting for scan completion...")
            time.sleep(3)
            
            # Test file report retrieval
            report = test_endpoint(
                "File Report", 
                f"{API_BASE}/files/{sha256}"
            )
            
            # Test search by hash
            test_endpoint(
                "Search by Hash", 
                f"{API_BASE}/search", 
                params={'q': sha256}
            )
            
            # Test search by filename
            test_endpoint(
                "Search by Filename", 
                f"{API_BASE}/search", 
                params={'q': 'enhanced'}
            )
            
            # Test authenticated endpoints
            auth_headers = {'Authorization': f'Bearer {API_KEY}'}
            
            # Test rescan
            test_endpoint(
                "File Rescan (authenticated)", 
                f"{API_BASE}/files/rescan",
                method='POST',
                headers=auth_headers,
                params={'sha256': sha256}
            )
            
            # Test URL scanning
            test_endpoint(
                "URL Scan (authenticated)", 
                f"{API_BASE}/urls",
                method='POST',
                headers=auth_headers,
                params={'url': 'https://example.com'}
            )
            
            # Test batch upload
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1, \
                 tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
                f1.write("Batch test file 1")
                f2.write("Batch test file 2")
                batch_file1, batch_file2 = f1.name, f2.name
            
            try:
                with open(batch_file1, 'rb') as f1, open(batch_file2, 'rb') as f2:
                    files = [
                        ('files', ('batch1.txt', f1, 'text/plain')),
                        ('files', ('batch2.txt', f2, 'text/plain'))
                    ]
                    test_endpoint(
                        "Batch Upload (authenticated)", 
                        f"{API_BASE}/files/batch",
                        method='POST',
                        headers=auth_headers,
                        files=files
                    )
            finally:
                os.unlink(batch_file1)
                os.unlink(batch_file2)
        
        # Test authentication failure
        test_endpoint(
            "URL Scan without auth (should fail)", 
            f"{API_BASE}/urls",
            method='POST',
            params={'url': 'https://example.com'}
        )
        
    finally:
        os.unlink(test_file)
    
    print("\n✅ Enhanced API testing completed!")

if __name__ == "__main__":
    main()