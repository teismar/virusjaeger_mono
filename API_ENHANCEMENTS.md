# Enhanced VirusJaeger API Documentation

The VirusJaeger API has been significantly enhanced to provide a comprehensive VirusTotal-like experience for both frontend applications and automation users.

## 🚀 New Features Added

### 1. **Enhanced API Structure**
- Improved FastAPI application with better documentation
- Professional API metadata and contact information
- Comprehensive error handling and validation

### 2. **Authentication System**
- Bearer token authentication for automation endpoints
- Demo API key: `demo-api-key` for testing
- Proper authorization checks for sensitive operations

### 3. **Comprehensive Endpoint Coverage**

#### **Public Endpoints** (No authentication required)
- `GET /health` - Health check
- `POST /files` - Upload files for scanning
- `GET /files/{sha256}` - Get scan reports
- `GET /search` - Search by filename or hash
- `GET /statistics` - System statistics
- `GET /urls/{scan_id}` - Get URL scan reports
- `GET /api-info` - API information and usage guide

#### **Authenticated Endpoints** (Require API key)
- `POST /files/rescan` - Rescan existing files
- `POST /urls` - Submit URLs for scanning
- `POST /files/batch` - Batch file upload (up to 10 files)

### 4. **Advanced Features**

#### **Mock Scanning System**
- Intelligent fallback when Celery/RabbitMQ is unavailable
- Realistic scan results with multiple engine simulation
- Proper status tracking (pending → finished)

#### **URL Scanning**
- Full URL validation and scanning capability
- Support for phishing and malware detection
- Unique scan ID generation for tracking

#### **Batch Operations**
- Upload multiple files simultaneously
- Individual result tracking per file
- Error handling for oversized or invalid files

#### **Enhanced Search**
- Search by filename (partial matching)
- Search by any hash type (MD5, SHA1, SHA256)
- Pagination and result limiting

#### **Statistics Dashboard**
- Real-time sample counts
- Scan status breakdown
- Engine information and versions

### 5. **Developer Experience**

#### **Comprehensive API Documentation**
- Auto-generated OpenAPI/Swagger documentation
- Detailed endpoint descriptions and examples
- Authentication flow documentation

#### **Error Handling**
- Proper HTTP status codes
- Descriptive error messages
- Input validation with clear feedback

#### **Testing Infrastructure**
- Comprehensive test script included
- All endpoints tested automatically
- Authentication flow validation

## 📚 Usage Examples

### Basic File Upload
```bash
curl -X POST "http://localhost:8000/files" \
  -F "file=@sample.exe"
```

### Authenticated URL Scanning
```bash
curl -X POST "http://localhost:8000/urls?url=https://example.com" \
  -H "Authorization: Bearer demo-api-key"
```

### Batch File Upload
```bash
curl -X POST "http://localhost:8000/files/batch" \
  -H "Authorization: Bearer demo-api-key" \
  -F "files=@file1.exe" \
  -F "files=@file2.exe"
```

### Search Operations
```bash
# Search by filename
curl "http://localhost:8000/search?q=malware"

# Search by hash
curl "http://localhost:8000/search?q=5d41402abc4b2a76b9719d911017c592"
```

## 🔧 Configuration

### Environment Variables
The API supports configuration through environment variables:
- `POSTGRES_DSN` - Database connection string
- `MAX_FILE_SIZE_MB` - Maximum file size limit (default: 64MB)
- `RABBITMQ_URL` - Message queue connection

### Local Development
For local development, the API automatically falls back to:
- SQLite database (`sqlite+aiosqlite:///./virusjaeger.db`)
- Mock scanning when Celery is unavailable
- In-memory API key storage

## 🚦 Rate Limiting & Quotas

The API includes built-in protection mechanisms:
- File size limits (configurable, default 64MB)
- Batch upload limits (max 10 files)
- API key quotas (configurable per key)
- Input validation and sanitization

## 🔐 Security Features

- API key authentication for sensitive operations
- Input validation and sanitization
- File type and size restrictions
- Proper error handling without information leakage

## 🧪 Testing

Run the comprehensive test suite:
```bash
python scripts/test_enhanced_api.py
```

This tests all endpoints, authentication flows, and error conditions.

## 🎯 VirusTotal Compatibility

The API provides equivalent functionality to major VirusTotal features:
- ✅ File upload and scanning
- ✅ Report retrieval
- ✅ Search functionality
- ✅ URL scanning
- ✅ Batch operations
- ✅ API key authentication
- ✅ Statistics and monitoring

## 🔄 Migration from Original API

The enhanced API is fully backward compatible with the original endpoints while adding new functionality. Existing integrations will continue to work without modification.