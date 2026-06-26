# S3 Bucket Security Scanner

A Python-based AWS S3 security scanner that detects common S3 bucket misconfigurations and classifies security risk levels using a rule-based approach.

## Features

* Detects public access through bucket policy
* Checks ACL-based public exposure
* Verifies server-side encryption status
* Checks bucket versioning configuration
* Classifies risk as HIGH, MEDIUM, or LOW
* Provides a simple Flask-based web interface
* Generates scan results in JSON format

## Tech Stack

* Python
* Flask
* Boto3
* AWS S3
* HTML
* CSS
* JSON

## How to Run

### 1. Configure AWS credentials

```bash
aws configure
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install manually:

```bash
pip install boto3 flask
```

### 3. Run the application

```bash
python app.py
```

### 4. Open in browser

```text
http://127.0.0.1:5000
```

Click **Run Scan** to view the S3 bucket security results.

## Sample Output

A safe sample scan result is available in:

```text
sample_s3_report.json
```

Example result:

```json
[
    {
        "bucket_name": "public-demo-bucket",
        "public_policy": true,
        "public_acl": false,
        "encryption": true,
        "versioning": "Disabled",
        "risk": "HIGH"
    },
    {
        "bucket_name": "secure-demo-bucket",
        "public_policy": false,
        "public_acl": false,
        "encryption": true,
        "versioning": "Disabled",
        "risk": "MEDIUM"
    }
]
```

Actual scan reports are ignored from GitHub to avoid exposing real AWS bucket names or sensitive environment details.

## Project Description

This project demonstrates how misconfigured AWS S3 buckets can create security risks such as public data exposure. The scanner checks bucket-level configurations including bucket policy, ACL, encryption, and versioning. Based on these checks, it assigns a simple risk level to help users understand and fix potential cloud storage security issues.

## UI Preview

Add a screenshot of the Flask web interface here.

## Author

Katimi Reddy Indu
