from flask import Flask, render_template, jsonify
import boto3
from scanner import scan_bucket

app = Flask(__name__)
s3 = boto3.client("s3")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan")
def scan_all_buckets():
    try:
        response = s3.list_buckets()
        buckets = response["Buckets"]

        results = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            if bucket_name in ["secure-bucket-nithin", "public-bucket-nithin"]:
                result = scan_bucket(bucket_name)
                results.append(result)

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False)
    