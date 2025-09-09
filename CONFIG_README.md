# Configuration Guide

This document explains how to configure the Scanner Cifrado S3 application.

## Quick Start

1. Copy the example configuration:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file with your settings:
   ```bash
   # For mock mode (testing)
   SCANNER_MOCK_MODE=true
   
   # For real scanner mode (production)
   SCANNER_MOCK_MODE=false
   SCANNER_DEVICE_ID=your_scanner_device_id
   ```

3. Configure S3 bucket:
   ```bash
   S3_BUCKET_NAME=your-bucket-name
   AWS_ACCESS_KEY_ID=your-access-key
   AWS_SECRET_ACCESS_KEY=your-secret-key
   ```

## Configuration Modes

### Mock Mode (Default)
- **Purpose**: Testing and development
- **Setting**: `SCANNER_MOCK_MODE=true`
- **Behavior**: 
  - Simulates scanner hardware
  - Generates mock documents automatically
  - No real scanner required

### Real Scanner Mode
- **Purpose**: Production with actual scanner
- **Setting**: `SCANNER_MOCK_MODE=false`
- **Requirements**:
  - Physical scanner connected
  - Scanner drivers installed
  - Scanner configuration set

## Scanner Configuration

### Scanner Types Supported
1. **TWAIN** (Windows): `SCANNER_TYPE=TWAIN`
2. **SANE** (Linux): `SCANNER_TYPE=SANE`  
3. **WIA** (Windows): `SCANNER_TYPE=WIA`

### Scanner Settings
```bash
# Scanner identification
SCANNER_NAME=Canon imageFORMULA DR-C225
SCANNER_MODEL=DR-C225

# Connection settings
SCANNER_DEVICE_ID=your_scanner_device_id
SCANNER_CONNECTION=USB  # USB, Network, Parallel
SCANNER_IP=192.168.1.100  # For network scanners
SCANNER_PORT=9100

# Timing settings
DOCUMENT_POLLING_INTERVAL=2  # Check every 2 seconds
SCANNER_TIMEOUT_SECONDS=30
SCANNER_RETRY_ATTEMPTS=3
```

## S3 Configuration

### Required Settings
```bash
S3_BUCKET_NAME=scanner-cifrado-docs  # REQUIRED
S3_BUCKET_REGION=us-east-1
```

### AWS Credentials
```bash
# Option 1: Environment variables (recommended)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Option 2: AWS Profile
AWS_PROFILE=your-profile-name
```

### Upload Settings
```bash
S3_KEY_PREFIX=encrypted-documents
S3_MULTIPART_THRESHOLD=100  # MB
S3_MAX_UPLOAD_ATTEMPTS=3
S3_UPLOAD_TIMEOUT=300  # seconds
```

## Application Settings

```bash
# Environment
APP_ENVIRONMENT=development  # development, staging, production

# Session
SESSION_TIMEOUT_MINUTES=60

# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR

# UI
UI_WINDOW_WIDTH=900
UI_WINDOW_HEIGHT=600
```

## Configuration Files

### Primary Configuration
- **`.env`**: Main configuration file (create from `.env.example`)
- **`src/config/settings.py`**: Configuration classes and defaults

### Helper Files
- **`.env.example`**: Template with all available options
- **`src/config/env_loader.py`**: Loads environment variables
- **`src/examples/config_usage.py`**: Shows current configuration

## Validation

Test your configuration:
```bash
python src/examples/config_usage.py
```

This will show:
- ✅ Current configuration summary
- ❌ Any configuration errors
- ⚠️ Configuration warnings

## Real Scanner Setup

### Windows (TWAIN/WIA)
1. Install scanner drivers
2. Test scanner with built-in Windows tools
3. Set configuration:
   ```bash
   SCANNER_MOCK_MODE=false
   SCANNER_TYPE=TWAIN  # or WIA
   SCANNER_NAME=Your Scanner Name
   ```

### Linux (SANE)
1. Install SANE: `sudo apt-get install libsane`
2. Install python-sane: `pip install python-sane`
3. Test scanner: `scanimage -L`
4. Set configuration:
   ```bash
   SCANNER_MOCK_MODE=false
   SCANNER_TYPE=SANE
   SCANNER_NAME=Your Scanner Name
   ```

## Security Notes

1. **Never commit `.env` to version control**
2. **Use IAM roles in production instead of access keys**
3. **Rotate credentials regularly**
4. **Use least-privilege access for S3 bucket**

## Troubleshooting

### Scanner Not Detected
1. Check `SCANNER_MOCK_MODE=false`
2. Verify scanner drivers installed
3. Test scanner with system tools
4. Check `SCANNER_DEVICE_ID` setting

### S3 Upload Failures
1. Verify bucket name exists
2. Check AWS credentials
3. Verify IAM permissions
4. Test network connectivity

### Configuration Errors
1. Run validation: `python src/examples/config_usage.py`
2. Check environment variable names
3. Verify file paths exist
4. Check data types (true/false, numbers)

## Environment Variable Priority

1. System environment variables (highest priority)
2. `.env` file values
3. Default values in `settings.py` (lowest priority)

This allows for flexible deployment across different environments.