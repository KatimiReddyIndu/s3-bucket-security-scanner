# S3 Bucket Security Scanner

This project is a Python-based AWS S3 security scanner that detects misconfigured buckets and classifies their risk levels.

## 🚀 Features
- Detects public access via bucket policy
- Checks ACL-based exposure
- Verifies encryption status
- Checks versioning configuration
- Classifies risk (HIGH / MEDIUM / LOW)
- Flask-based web UI

## 🛠️ Tech Stack
- Python (boto3)
- Flask
- AWS S3

## ⚙️ How to Run

1. Configure AWS:
2. aws configure


2. Install required dependencies:


pip install boto3 flask


3. Run the application:


python app.py


4. Open browser and go to:


http://127.0.0.1:5000


5. Click **Run Scan** to view results

---

## 📊 Sample Output

- public-bucket-nithin → HIGH risk  
- secure-bucket-nithin → MEDIUM risk  

---

## 📌 Project Description

This project demonstrates how misconfigured AWS S3 buckets can lead to serious security risks such as public data exposure. The system automatically scans bucket configurations and provides a simple rule-based risk classification to help users understand and fix vulnerabilities.

---

## 📸 UI Preview

(Add your screenshot here if needed)

---

## 👤 Author

Nukala Nithin Reddy
