import os
import subprocess
import json
import time
import requests
import re
import uuid
import codeql_scanner
from dotenv import load_dotenv

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATIONS ---
BASE_REPO = "./juice-shop"
RESULTS_DIR_LOCAL = "./experiment_results/local/juice-shop"
RESULTS_DIR_OCI = "./experiment_results/oci/juice-shop"
REPORTS_BASE_DIR = "./experiment_results/reports"
TARGET_URL = "http://localhost:3000"
APP_STARTUP_TIMEOUT = 180 

# Define qual ambiente testar (default: 'all' testa ambos e a baseline)
PROVIDER = os.getenv("PROVIDER", "all").lower()
SONAR_LOGIN = os.getenv("SONAR_LOGIN", "admin")
SONAR_PASS = os.getenv("SONAR_PASS", "admin")

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
    
    build_success = True
    
    if not os.path.exists(f"{target_dir}/node_modules"):
        ok, _ = run_command(["npm", "install", "--legacy-peer-deps"], "Installation", cwd=target_dir)
        if not ok: build_success = False
    
    # Adicionamos ignore_error=True para o script continuar mesmo se o tsc falhar
    ok, _ = run_command(["npm", "run", "build:server"], "Build Backend", cwd=target_dir, ignore_error=True)
    if not ok: build_success = False
    
    ok, _ = run_command(["npm", "run", "build:frontend"], "Build Frontend", cwd=target_dir, ignore_error=True)
    if not ok: build_success = False
    
    print("   ℹ️  Running server unit tests...")
    back_ok, back_out = run_command(["npm", "run", "test:server"], "Unit Tests (Server)", cwd=target_dir, ignore_error=True)
    back_passed = extract_test_passing_count(back_out, "mocha")
    
    print("   ℹ️  Running frontend unit tests...")
    frontend_path = os.path.join(target_dir, "frontend")
    front_cmd = ["npm", "run", "test", "--", "--watch=false", "--browsers=ChromiumHeadless"]
    
    front_ok, front_out = run_command(front_cmd, "Unit Tests (Frontend)", cwd=frontend_path, ignore_error=True)
    front_passed = extract_test_passing_count(front_out, "karma")
    
    return build_success, back_passed, front_passed

def inject_sonar_properties(target_dir, run_id):
    print(f"   📝 Injecting sonar-project.properties...", end=" ", flush=True)
    properties_path = os.path.join(target_dir, "sonar-project.properties")
    content = f"""sonar.projectKey={run_id}
sonar.projectName=Juice Shop - {run_id}
sonar.sources=.
sonar.exclusions=node_modules/**,frontend/node_modules/**,data/**,test/**,e2e/**,build/**,dist/**,**/*.spec.ts,reports/**
sonar.language=ts
sonar.javascript.lcov.reportPaths=build/reports/coverage/frontend-tests/lcov.info,build/reports/coverage/server-tests/lcov.info
"""
    try:
        with open(properties_path, "w") as f:
            f.write(content)
        print("✅ OK")
    except Exception as e:
        print(f"❌ Error: {e}")

def run_sast_codeQL(target_dir, report_dir):
    print(f"\n[SAST] Starting CodeQL...", flush=True)
    scan_result = codeql_scanner.run_scan(target_dir, report_dir)
    return scan_result.get("total", -1)

def run_sonarqube_scan(target_dir, run_id):
    print(f"\n[CODE QUALITY] Starting SonarQube Scan for {run_id}...", flush=True)
    abs_target_dir = os.path.abspath(target_dir)
    
    inject_sonar_properties(abs_target_dir, run_id)
    
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-e", "SONAR_HOST_URL=http://localhost:9000",
        "-e", f"SONAR_LOGIN={SONAR_LOGIN}",
        "-e", f"SONAR_PASSWORD={SONAR_PASS}",
        "-v", f"{abs_target_dir}:/usr/src:z",
        "sonarsource/sonar-scanner-cli"
    ]
    
    print(f"   ℹ️  Running Scanner...")
    # 👇 Mudamos para ignore_error=False para o Python cuspir o erro na tela se falhar
    success, output = run_command(cmd, "SonarScanner", cwd=target_dir, ignore_error=False)
    if not success:
        return -1, -1, -1, -1, -1
        
    print(f"   ℹ️  Waiting for SonarQube background task to finish...", end="", flush=True)
    api_url = f"http://localhost:9000/api/measures/component?component={run_id}&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,sqale_index"
    
    metrics = {'bugs': -1, 'vulnerabilities': -1, 'code_smells': -1, 'security_hotspots': -1, 'sqale_index': -1}
    
    for _ in range(30):
        time.sleep(3)
        print(".", end="", flush=True)
        try:
            response = requests.get(api_url, auth=(SONAR_LOGIN, SONAR_PASS))
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

def create_zap_hook(report_dir):
    """Gera um arquivo de hook do ZAP para forçar a importação da OpenAPI/Swagger."""
    hook_path = os.path.join(report_dir, "zap_hook.py")
    hook_code = """
def zap_started(zap, target):
    print(f"\\n[ZAP HOOK] Importing OpenAPI Definitions from {target}/api-docs...")
    try:
        zap.openapi.import_url(f"{target}/api-docs")
        print("[ZAP HOOK] OpenAPI import complete.\\n")
    except Exception as e:
        print(f"[ZAP HOOK] Failed to import OpenAPI: {e}\\n")
"""
    with open(hook_path, "w") as f:
        f.write(hook_code)
    return "zap_hook.py"

def run_dast_zap(report_dir):
    print(f"\n[DAST] Starting ZAP Full Scan (Ajax + OpenAPI + Auth)...", flush=True)
    
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
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "createdAt": "2021-12-11T12:00:00.000Z", "updatedAt": "2021-12-11T12:00:00.000Z"},
        "securityAnswer": "ZapBot"
    }
    
    try:
        time.sleep(10) # Aguarda o backend do Juice Shop estabilizar
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
    
    hook_filename = create_zap_hook(abs_report_dir)
    
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
        "-j", # Ativa o Ajax Spider para a SPA Angular
        "-a", # Ativa o Active Scan
        "-d",
        "--hook", f"/zap/wrk/{hook_filename}"
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
    print(f"🛡️ BATCH SECURITY EVALUATION (Provider: {PROVIDER.upper()})")
    print("="*60)
    
    os.makedirs(REPORTS_BASE_DIR, exist_ok=True)
    
    run_dirs = []
    
    # 1. Baseline (Sem refatoração) SOMENTE se PROVIDER for 'all'
    if PROVIDER == "all" and os.path.exists(BASE_REPO):
        run_dirs.append(("baseline-original", BASE_REPO))
    
    # 2. Experimentos Locais (Llama 3.1 8B)
    if PROVIDER in ["local", "all"] and os.path.exists(RESULTS_DIR_LOCAL):
        for d in os.listdir(RESULTS_DIR_LOCAL):
            dir_path = os.path.join(RESULTS_DIR_LOCAL, d)
            if os.path.isdir(dir_path) and d != "reports":
                run_dirs.append((f"local-{d}", dir_path))
                
    # 3. Experimentos OCI (Llama 3.3 70B)
    if PROVIDER in ["oci", "all"] and os.path.exists(RESULTS_DIR_OCI):
        for d in os.listdir(RESULTS_DIR_OCI):
            dir_path = os.path.join(RESULTS_DIR_OCI, d)
            if os.path.isdir(dir_path) and d != "reports":
                run_dirs.append((f"oci-{d}", dir_path))

    if len(run_dirs) == 0: 
        print(f"⚠️ No target directories found for provider '{PROVIDER}'. Check your .env or paths.")
        return

    sec_csv_path = os.path.join(REPORTS_BASE_DIR, "security_metrics.csv")
    tests_csv_path = os.path.join(REPORTS_BASE_DIR, "unit_tests_metrics.csv")
    
    # Prepara os CSVs se não existirem
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
        metrics["integrity"] = integrity_ok

        with open(tests_csv_path, "a") as f:
            f.write(f"{run_id},{back_passed},{front_passed}\n")

        # RODA O SAST (SONAR E CODEQL) MESMO SE A COMPILAÇÃO TIVER FALHADO!
        metrics["sast"] = run_sast_codeQL(target_dir, report_dir)
        metrics["sonar"] = run_sonarqube_scan(target_dir, run_id)
        
        # Tenta subir a aplicação. Se o LLM quebrou tudo, o app_process será None
        app_process = wait_for_app(target_dir, report_dir)
        if app_process:
            metrics["dast"] = run_dast_zap(report_dir)
            app_process.kill()
            force_kill_port(3000)
        else:
            print(f"⚠️ App failed to start for {run_id} due to LLM breaking the code. Skipping DAST.")

        # Escreve os resultados!
        sb, sv, scs, sh, sq = metrics["sonar"]
        with open(sec_csv_path, "a") as f:
            f.write(f"{run_id},{metrics['integrity']},{metrics['sast']},{metrics['dast']},{sb},{sv},{scs},{sh},{sq}\n")

if __name__ == "__main__":
    run_experiment()