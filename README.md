# AWS Cloud Security Posture Monitoring (CSPM) Tool

This tool scans your AWS environment for common security misconfigurations and risks:

- Detects publicly accessible S3 buckets  
- Identifies IAM roles with `AdministratorAccess` policy attached  
- Finds security groups with open inbound rules to the world (`0.0.0.0/0`)  

Optionally, it can remediate these issues interactively.

---

## Requirements

- Python 3.7+
- `boto3` AWS SDK for Python
- AWS credentials configured with sufficient permissions

---

## Setup

1. Clone the repo:

    ```bash
    git clone <your-repo-url>
    cd aws-cspm-tool
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Configure AWS credentials using:

    ```bash
    aws configure
    ```

---

## Usage

Run the CSPM tool:

    ```bash
    python cspm_aws.py

## License

This project is licensed under the [MIT License](LICENSE).

