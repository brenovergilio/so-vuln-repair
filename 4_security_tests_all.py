import os
import subprocess
import json
import time
import requests
import re
import uuid
import codeql_scanner

# --- CONFIGURATIONS ---
BASE_REPO = "./juice-shop"
RESULTS_DIR = "./experiment_results/juice-shop"
REPORTS_BASE_DIR = os.path.join(RESULTS_DIR, "reports")
TARGET_URL = "http://localhost:3000"
APP_STARTUP_TIMEOUT = 180 

def run_command(command_list, step_name, cwd, ignore_error=False):
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

def extract_test_passing_count(output, framework):
    if not output: return 0
    try:
        if framework == "mocha":
            match = re.search(r'(\d+)\s+passing', output, re.IGNORECASE)
            return int(match.group(1)) if match else 0
        elif framework == "karma":
            exec_match = re.search(r'Executed\s+(\d+)\s+of\s+\d+', output, re.IGNORECASE)
            if not exec_match: return 0
            executed = int(exec_match.group(1))
            
            fail_match = re.search(r'\((\d+)\s+FAILED\)', output, re.IGNORECASE)
            failed = int(fail_match.group(1)) if fail_match else 0
            
            return executed - failed
    except:
        return 0
    return 0

def check_deep_integrity(target_dir, run_id):
    print(f"\n[DEEP INTEGRITY CHECK] Validating environment...", flush=True)
    force_kill_port(3000)
    
    if not os.path.exists(f"{target_dir}/node_modules"):
        ok, _ = run_command(["npm", "install", "--legacy-peer-deps"], "Installation", cwd=target_dir)
        if not ok: return False, 0, 0
    
    ok, _ = run_command(["npm", "run", "build:server"], "Build Backend", cwd=target_dir)
    if not ok: return False, 0, 0
    ok, _ = run_command(["npm", "run", "build:frontend"], "Build Frontend", cwd=target_dir)
    if not ok: return False, 0, 0
    
    print("   ℹ️  Running server unit tests...")
    back_ok, back_out = run_command(["npm", "run", "test:server"], "Unit Tests (Server)", cwd=target_dir, ignore_error=True)
    back_passed = extract_test_passing_count(back_out, "mocha")
    
    print("   ℹ️  Running frontend unit tests...")
    frontend_path = os.path.join(target_dir, "frontend")
    front_cmd = ["npm", "run", "test", "--", "--watch=false", "--browsers=ChromiumHeadless"]
    
    front_ok, front_out = run_command(front_cmd, "Unit Tests (Frontend)", cwd=frontend_path, ignore_error=True)
    front_passed = extract_test_passing_count(front_out, "karma")
    
    return True, back_passed, front_passed

def run_sast_codeQL(target_dir, report_dir):
    print(f"\n[SAST] Starting CodeQL...", flush=True)
    scan_result = codeql_scanner.run_scan(target_dir, report_dir)
    return scan_result.get("total", -1)

def run_sonarqube_scan(target_dir, run_id):
    print(f"\n[CODE QUALITY] Starting SonarQube Scan for {run_id}...", flush=True)
    abs_target_dir = os.path.abspath(target_dir)
    
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-e", "SONAR_HOST_URL=http://localhost:9000",
        "-e", "SONAR_LOGIN=admin",
        "-e", "SONAR_PASSWORD=admin",
        "-v", f"{abs_target_dir}:/usr/src",
        "sonarsource/sonar-scanner-cli",
        f"-Dsonar.projectKey={run_id}",
        "-Dsonar.sources=.",
        "-Dsonar.exclusions=node_modules/**,frontend/node_modules/**,dist/**,build/**,test/**,coverage/**"
    ]
    
    print(f"   ℹ️  Running Scanner...")
    success, _ = run_command(cmd, "SonarScanner", cwd=target_dir, ignore_error=True)
    if not success:
        return -1, -1, -1, -1, -1
        
    print(f"   ℹ️  Waiting for SonarQube background task to finish...", end="", flush=True)
    api_url = f"http://localhost:9000/api/measures/component?component={run_id}&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,sqale_index"
    
    metrics = {'bugs': -1, 'vulnerabilities': -1, 'code_smells': -1, 'security_hotspots': -1, 'sqale_index': -1}
    
    for _ in range(15):
        time.sleep(3)
        print(".", end="", flush=True)
        try:
            response = requests.get(api_url, auth=('admin', 'admin'))
            if response.status_code == 200:
                measures = response.json().get('component', {}).get('measures', [])
                for m in measures:
                    metrics[m['metric']] = int(m['value'])
                
                print(" ✅ OK")
                print(f"   📊 SONARQUBE METRICS:")
                print(f"      - Bugs: {metrics['bugs']}")
                print(f"      - Vulnerabilities (SAST): {metrics['vulnerabilities']}")
                print(f"      - Security Hotspots: {metrics['security_hotspots']}")
                print(f"      - Code Smells: {metrics['code_smells']}")
                print(f"      - Tech Debt (mins): {metrics['sqale_index']}")
                
                return metrics['bugs'], metrics['vulnerabilities'], metrics['code_smells'], metrics['security_hotspots'], metrics['sqale_index']
        except:
            pass

    print(" ❌ Timeout or API Error")
    return -1, -1, -1, -1, -1

def wait_for_app(target_dir, report_dir):
    print(f"\n[SETUP] Starting Juice Shop...", flush=True)
    force_kill_port(3000)
    
    log_file = open(f"{report_dir}/app_runtime.log", "w")
    server_process = subprocess.Popen(["npm", "start"], cwd=target_dir, stdout=log_file, stderr=subprocess.STDOUT)
    
    start_time = time.time()
    while time.time() - start_time < APP_STARTUP_TIMEOUT:
        try:
            if requests.get(TARGET_URL).status_code == 200:
                print("✅ Juice Shop Online!")
                return server_process
        except: pass
        time.sleep(2)
        print(".", end="", flush=True)
    
    print("\n❌ Timeout: Application did not start.")
    try: server_process.kill()
    except: pass
    return None

def run_dast_zap(report_dir):
    print(f"\n[DAST] Starting ZAP Full Scan (Authenticated as New User)...", flush=True)
    
    unique_id = uuid.uuid4().hex[:8]
    email = f"zap_scanner_{unique_id}@juice-sh.op"
    password = "ZapPassword123!"
    jwt_token = ""

    print(f"   👤 Registering new account ({email})...", end=" ", flush=True)
    register_url = f"{TARGET_URL}/api/Users/"
    register_data = {
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {
            "id": 1,
            "question": "Your eldest siblings middle name?",
            "createdAt": "2021-12-11T12:00:00.000Z",
            "updatedAt": "2021-12-11T12:00:00.000Z"
        },
        "securityAnswer": "ZapBot"
    }
    
    try:
        time.sleep(10)
        reg_resp = requests.post(register_url, json=register_data, timeout=10)
        
        if reg_resp.status_code in [200, 201]:
            print("✅ OK")
            print(f"   🔑 Logging in to retrieve JWT...", end=" ", flush=True)
            login_url = f"{TARGET_URL}/rest/user/login"
            login_data = {"email": email, "password": password}
            
            log_resp = requests.post(login_url, json=login_data, timeout=10)
            if log_resp.status_code == 200:
                jwt_token = log_resp.json().get('authentication', {}).get('token', '')
                print("✅ OK")
            else:
                print(f"⚠️ Login Failed (HTTP {log_resp.status_code}). ZAP will run unauthenticated.")
        else:
            print(f"⚠️ Registration Failed (HTTP {reg_resp.status_code}). ZAP will run unauthenticated.")
    except Exception as e:
        print(f"❌ Error during auth flow: {e}. ZAP will run unauthenticated.")

    try: os.chmod(report_dir, 0o777)
    except: pass
    abs_report_dir = os.path.abspath(report_dir)
    
    cmd = [
        "docker", "run", "--rm", 
        "--network", "host",
        "-u", "0",
        "-v", f"{abs_report_dir}:/zap/wrk/:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-full-scan.py",
        "-t", TARGET_URL,
        "-J", "zap_results.json",
        "-r", "zap_report.html",
        "-j", 
        "-a",
        "-d"
    ]
    
    if jwt_token:
        auth_header = f"Bearer {jwt_token}"
        replacer_rules = [
            "-config", "replacer.full_list(0).description=auth_jwt",
            "-config", "replacer.full_list(0).enabled=true",
            "-config", "replacer.full_list(0).matchtype=req_header",
            "-config", "replacer.full_list(0).matchstr=Authorization",
            "-config", "replacer.full_list(0).regex=false",
            "-config", f"replacer.full_list(0).replacement={auth_header}"
        ]
        cmd.extend(replacer_rules)
    
    print(f"   ℹ️  Attacking Target with Spider & Auth (This will take a while)...")
    try:
        subprocess.run(cmd, capture_output=True, text=True)
        json_path = os.path.join(report_dir, "zap_results.json")
        
        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            with open(json_path, 'r') as f:
                data = json.load(f)
                
            alerts_list = data.get('site', [{}])[0].get('alerts', [])
            total_instances = 0
            
            print(f"\n   📊 DETAILS ABOUT ALERTS (FULL SCAN):")
            print(f"   {'-'*60}")
            print(f"   {'ALERT NAME':<45} | {'RISK':<10} | {'QTD'}")
            print(f"   {'-'*60}")
            
            for alert in alerts_list:
                name = alert.get('name', 'Unknown')[:43]
                risk = alert.get('riskdesc', 'UNK').split(' ')[0]
                count = len(alert.get('instances', []))
                
                if risk != "Informational":
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
    print("="*60)
    print("🛡️ BATCH SECURITY EVALUATION (Baseline + LLM Runs)")
    print("="*60)
    
    os.makedirs(REPORTS_BASE_DIR, exist_ok=True)
    
    run_dirs = []
    if os.path.exists(BASE_REPO):
        run_dirs.append(("original", BASE_REPO))
    
    if os.path.exists(RESULTS_DIR):
        for d in os.listdir(RESULTS_DIR):
            dir_path = os.path.join(RESULTS_DIR, d)
            if os.path.isdir(dir_path) and d != "reports":
                run_dirs.append((d, dir_path))

    if not run_dirs:
        print("⚠️ No target directories found.")
        return

    sec_csv_path = os.path.join(RESULTS_DIR, "security_metrics.csv")
    tests_csv_path = os.path.join(RESULTS_DIR, "unit_tests_metrics.csv")
    
    if not os.path.exists(sec_csv_path):
        with open(sec_csv_path, "w") as f:
            f.write("Run_ID,Integrity_Passed,SAST_Vulnerabilities,DAST_Vulnerabilities,Sonar_Bugs,Sonar_Vulnerabilities,Sonar_Smells,Sonar_Hotspots,Sonar_Debt_Mins\n")
            
    if not os.path.exists(tests_csv_path):
        with open(tests_csv_path, "w") as f:
            f.write("Run_ID,Backend_Tests_Passed,Frontend_Tests_Passed\n")

    for run_id, target_dir in run_dirs:
        report_dir = os.path.join(REPORTS_BASE_DIR, run_id)
        os.makedirs(report_dir, exist_ok=True)

        print(f"\n" + "="*50)
        print(f"🔬 EVALUATING REPOSITORY: {run_id}")
        print("="*50)

        metrics = {"integrity": False, "sast": -1, "dast": -1, "sonar": (-1, -1, -1, -1, -1)}
        
        integrity_ok, back_passed, front_passed = check_deep_integrity(target_dir, run_id)

        with open(tests_csv_path, "a") as f:
            f.write(f"{run_id},{back_passed},{front_passed}\n")

        if integrity_ok:
            metrics["integrity"] = True
            
            # 1. SAST CodeQL
            metrics["sast"] = run_sast_codeQL(target_dir, report_dir)
            
            # 2. SAST + Qualidade SonarQube
            metrics["sonar"] = run_sonarqube_scan(target_dir, run_id)
            
            # 3. DAST ZAP
            app_process = wait_for_app(target_dir, report_dir)
            if app_process:
                metrics["dast"] = run_dast_zap(report_dir)
                app_process.kill()
                force_kill_port(3000)
            else:
                print(f"⚠️ App failed to start for {run_id}. Skipping DAST.")
        else:
            print(f"⛔ Integrity checks failed for {run_id}. Code is broken. Skipping SAST/DAST.")

        # Escrevendo métricas no CSV incluindo o pacote SonarQube desempacotado
        sb, sv, scs, sh, sq = metrics["sonar"]
        with open(sec_csv_path, "a") as f:
            f.write(f"{run_id},{metrics['integrity']},{metrics['sast']},{metrics['dast']},{sb},{sv},{scs},{sh},{sq}\n")

if __name__ == "__main__":
    run_experiment()