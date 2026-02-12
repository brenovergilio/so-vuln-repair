import os
import subprocess
import json

IMAGE_NAME = "codeql-scanner"
DB_NAME = "juiceshop-db"

DOCKERFILE_CONTENT = """
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y wget curl git python3 build-essential && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_18.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && \
    apt-get install -y nodejs
ARG BUNDLE_URL=https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.24.1/codeql-bundle-linux64.tar.gz
WORKDIR /opt/codeql
RUN wget -q "$BUNDLE_URL" -O codeql-bundle.tar.gz && \
    tar -xf codeql-bundle.tar.gz && \
    rm codeql-bundle.tar.gz
RUN chmod -R 777 /opt/codeql
ENV PATH="/opt/codeql/codeql:${PATH}"
WORKDIR /target
"""

def _build_image_if_missing():
    try:
        subprocess.run(["docker", "inspect", IMAGE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except:
        print(f"🔨 [CodeQL Module] Building Docker image '{IMAGE_NAME}'...")
        with open("Dockerfile.temp", "w") as f:
            f.write(DOCKERFILE_CONTENT)
        try:
            subprocess.run(["docker", "build", "-t", IMAGE_NAME, "-f", "Dockerfile.temp", "."], check=True)
            print("✅ Image ready.")
        finally:
            if os.path.exists("Dockerfile.temp"): os.remove("Dockerfile.temp")

def _parse_results(sarif_path):
    if not os.path.exists(sarif_path):
        return {"total": -1, "alerts": []}

    try:
        with open(sarif_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        results = data.get('runs', [])[0].get('results', [])
        
        summary = {
            "total": len(results),
            "alerts": []
        }
        
        for res in results[:5]:
            msg = res.get('message', {}).get('text', 'No description')
            rule = res.get('ruleId', 'Unknown rule')
            summary["alerts"].append(f"[{rule}] {msg}")
            
        return summary
    except Exception as e:
        print(f"⚠️  Error parsing SARIF: {e}")
        return {"total": -1, "error": str(e)}

def run_scan(target_dir, output_dir):
    abs_target = os.path.abspath(target_dir)
    abs_output = os.path.abspath(output_dir)
    
    os.makedirs(abs_output, exist_ok=True)
    _build_image_if_missing()
    
    docker_cmd = f"""
    codeql database create /tmp/{DB_NAME} \
        --language=javascript \
        --source-root=. \
        --overwrite \
        --command="npm install --legacy-peer-deps --ignore-scripts" > /dev/null && \
    
    codeql database analyze /tmp/{DB_NAME} javascript-security-extended.qls \
        --format=sarif-latest --output=/reports/result.sarif > /dev/null && \
        
    codeql database analyze /tmp/{DB_NAME} javascript-security-extended.qls \
        --format=csv --output=/reports/result.csv > /dev/null
    """

    uid = os.getuid()
    gid = os.getgid()

    cmd = [
        "docker", "run", "--rm",
        "-e", "HOME=/tmp",
        "-v", f"{abs_target}:/target",
        "-v", f"{abs_output}:/reports",
        "--user", f"{uid}:{gid}",
        IMAGE_NAME,
        "bash", "-c", docker_cmd
    ]

    try:
        subprocess.run(cmd, check=True)
        
        sarif_file = os.path.join(abs_output, "result.sarif")
        return _parse_results(sarif_file)
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Docker execution failed for {target_dir}: {e}")
        return {"total": -1, "error": "Docker failed"}
