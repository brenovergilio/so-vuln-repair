import os
import subprocess
import json
import time
import requests

# --- CONFIGURATIONS ---
TARGET_DIR = "./juice-shop"
REPORT_DIR = "./security_reports"
TARGET_URL = "http://localhost:3000"
SWAGGER_URL = "https://raw.githubusercontent.com/juice-shop/juice-shop/master/swagger.yml"
APP_STARTUP_TIMEOUT = 180 

os.makedirs(REPORT_DIR, exist_ok=True)

def run_command(command_list, step_name, cwd=TARGET_DIR, ignore_error=False):
    print(f"   ⏳ [{step_name}] Executing...", end=" ", flush=True)
    try:
        result = subprocess.run(
            command_list, cwd=cwd, check=True, 
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        print("✅ OK")
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        print("❌ FAILED")
        if not ignore_error:
            print(f"\n--- ERROR IN {step_name} ---")
            log_content = e.stdout if e.stdout else "⚠️ No output captured."
            print(log_content[-3000:]) 
            print("------------------------------------------------")
        return False, e.stdout

def force_kill_port(port=3000):
    print(f"   🧹 [CLEANUP] Opening {port} port...", end=" ", flush=True)
    subprocess.run(["fuser", "-k", "-s", "9", f"{port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        subprocess.run(f"lsof -t -i:{port} | xargs -r kill -9", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass
    time.sleep(1)
    print("✅ OK")

def check_deep_integrity():
    print(f"\n[DEEP INTEGRITY CHECK] Validating environment...", flush=True)
    force_kill_port(3000)
    
    if not os.path.exists(f"{TARGET_DIR}/node_modules"):
        ok, _ = run_command(["npm", "install"], "Installation (npm install)")
        if not ok: return False
    
    ok, _ = run_command(["npm", "run", "build:server"], "Build Backend")
    if not ok: return False
    ok, _ = run_command(["npm", "run", "build:frontend"], "Build Frontend")
    if not ok: return False
    
    force_kill_port(3000) 
    print("   ℹ️  Running server unit tests...")
    ok, _ = run_command(["npm", "run", "test:server"], "Unit Tests (Server)")
    return ok

def run_sast_semgrep():
    print(f"\n[SAST] Starting Semgrep...", flush=True)
    output_file = f"{REPORT_DIR}/semgrep_results.json"
    
    cmd = [
        "semgrep", "scan",
        "--config", "p/javascript", "--config", "p/typescript",
        "--config", "p/owasp-top-ten", "--config", "p/security-audit",
        "--config", "p/nodejsscan", "--config", "p/expressjs", 
        "--config", "p/secrets", "--config", "p/sql-injection",
        "--json", "--output", output_file, TARGET_DIR
    ]
    
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(output_file, 'r') as f:
            data = json.load(f)
            total = len(data.get('results', []))
            print(f"✅ SAST Finished: {total} detected issues.")
            return total
    except Exception as e:
        print(f"❌ Error in SAST: {e}")
        return 0

def wait_for_app():
    print(f"[SETUP] Starting Juice Shop...", flush=True)
    force_kill_port(3000)
    
    log_file = open(f"{REPORT_DIR}/app_runtime.log", "w")
    server_process = subprocess.Popen(["npm", "start"], cwd=TARGET_DIR, stdout=log_file, stderr=subprocess.STDOUT)
    
    start_time = time.time()
    while time.time() - start_time < APP_STARTUP_TIMEOUT:
        try:
            if requests.get(TARGET_URL).status_code == 200:
                print("✅ Juice Shop Online!")
                return server_process
        except: pass
        time.sleep(2)
        print(".", end="", flush=True)
    
    print("\n❌ Timeout: Application did not started.")
    try: server_process.kill()
    except: pass
    return None

def run_dast_zap():
    print(f"\n[DAST] Starting ZAP API SCAN...", flush=True)
    
    swagger_path = os.path.abspath(f"{REPORT_DIR}/swagger.yml")
    if not os.path.exists(swagger_path):
        print(f"   ⬇️  Downloading Swagger...", end=" ", flush=True)
        try:
            r = requests.get(SWAGGER_URL)
            with open(swagger_path, 'wb') as f: f.write(r.content)
            print("✅ OK")
        except Exception as e:
            print(f"❌ Error in download: {e}")

    try: os.chmod(REPORT_DIR, 0o777)
    except: pass
    abs_report_dir = os.path.abspath(REPORT_DIR)
    
    cmd = [
        "docker", "run", "--rm", 
        "--network", "host",
        "-u", "0",
        "-v", f"{abs_report_dir}:/zap/wrk/:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-api-scan.py",
        "-t", "/zap/wrk/swagger.yml",
        "-f", "openapi",
        "-O", TARGET_URL,
        "-J", "zap_results.json",
        "-r", "zap_report.html",
        "-a",
        "-d",
        "-I",
        "-z",
        "-config scanner.strength=HIGH -config scanner.threadPerHost=10 -config scanner.attackOn404=true"
    ]   
    
    print(f"   ℹ️  Attacking API...")
    try:
        subprocess.run(cmd, capture_output=True, text=True)
        json_path = os.path.join(REPORT_DIR, "zap_results.json")
        
        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            with open(json_path, 'r') as f:
                data = json.load(f)
                
            alerts_list = data.get('site', [{}])[0].get('alerts', [])
            total_instances = 0
            
            print(f"\n   📊 DETAILS ABOUT ALERTS (API SCAN):")
            print(f"   {'-'*60}")
            print(f"   {'ALERT NAME':<45} | {'RISK':<10} | {'QTD'}")
            print(f"   {'-'*60}")
            
            for alert in alerts_list:
                name = alert.get('name', 'Unknown')[:43]
                risk = alert.get('riskdesc', 'UNK').split(' ')[0]
                count = len(alert.get('instances', []))
                
                print(f"   {name:<45} | {risk:<10} | {count}")
                total_instances += count
            
            print(f"   {'-'*60}")
            print(f"   ✅ TOTAL DAST: {total_instances}")
            return total_instances

        return 0
    except Exception as e:
        print(f"❌ Error in Python: {e}")
        return 0

def run_experiment():
    print("="*50)
    print("🔬 SECURITY TESTS")
    print("="*50)
    metrics = {"integrity_status": False, "sast_count": 0, "dast_count": 0, "timestamp": time.time()}

    if check_deep_integrity():
        metrics["integrity_status"] = True
        metrics["sast_count"] = run_sast_semgrep()
        app_process = wait_for_app()
        if app_process:
            metrics["dast_count"] = run_dast_zap()
            app_process.kill()
            force_kill_port(3000)
    else:
        print("⛔ ABORTING.")

    with open(f"{REPORT_DIR}/audit_metrics.json", "w") as f: json.dump(metrics, f, indent=4)
    print("\n" + "="*50)
    print(f"FINAL METRICS:\nIntegrity: {'✅ OK' if metrics['integrity_status'] else '❌ FAILED'}")
    print(f"SAST: {metrics['sast_count']} | DAST: {metrics['dast_count']}")
    print("="*50)

if __name__ == "__main__":
    run_experiment()