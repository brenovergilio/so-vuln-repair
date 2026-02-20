import os
import time
import shutil
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from tree_sitter_languages import get_language, get_parser
from dotenv import load_dotenv

# --- CUSTOM MODULES ---
from oci_client import OCIClient
import codeql_scanner

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATION ---
BASE_REPO = "./juice-shop"
OUTPUT_DIR = "./experiment_results/juice-shop"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 3))

# Files to analyze
TARGET_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}
# Important directories in Juice Shop
TARGET_DIRS = {"routes", "lib", "models", "data", "frontend/src/app"} 
# Directories to ignore
IGNORE_DIRS = {"node_modules", ".git", "test", "dist", ".angular", "e2e", "vagrant"}

# --- OCI PRICING CONFIGURATION ---
# A OCI cobra a categoria "Large Meta" (Llama 3.1 70B Instruct) a $0.0018 por 10.000 caracteres.
OCI_PRICE_PER_10K_CHARS = 0.0018
CHARS_PER_TOKEN_ESTIMATE = 4

# --- SYSTEM PROMPTS (ENGLISH) ---
PROMPT_RAW = """You are a Secure Code Assistant. 
Refactor the provided JavaScript/TypeScript function to fix any potential security vulnerabilities.
RULES:
1. KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
2. RETURN ONLY THE CODE. No markdown, no explanation.
3. If the code is safe, return it exactly as is.
"""

PROMPT_RAG = """You are a Secure Code Assistant equipped with vulnerability knowledge.
Using the provided CONTEXT about known vulnerabilities in this project, refactor the function to be secure.
RULES:
1. KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
2. RETURN ONLY THE CODE. No markdown, no explanation.
3. If the code is safe, return it exactly as is.
4. Use the context to apply specific fixes.
"""

# --- TREE-SITTER SETUP ---
language = get_language('javascript')
parser = get_parser('javascript')

try:
    oci_bot = OCIClient()
except Exception as e:
    print(f"❌ FATAL: Could not initialize OCI Client. Check .env file. Error: {e}")
    exit(1)

def count_syntax_errors(tree):
    """Conta quantos nós de erro existem na árvore sintática."""
    query = language.query("(ERROR) @err")
    captures = query.captures(tree.root_node)
    return len(captures)

def extract_functions(code_bytes):
    tree = parser.parse(code_bytes)
    
    query_scm = """
    (function_declaration) @func
    (function_expression) @func
    (arrow_function) @func
    (method_definition) @func
    """
    query = language.query(query_scm)
    captures = query.captures(tree.root_node)
    
    funcs = []
    for node, _ in captures:
        length = node.end_byte - node.start_byte
        funcs.append((node.start_byte, node.end_byte, length))
        
    return funcs

def clean_llm_response(response, original_code):
    if not response: 
        return original_code
        
    match = re.search(r'```(?:javascript|typescript|js|ts)?\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
    
    if match:
        return match.group(1).strip()
    
    return response.strip()

def calculate_cost_oci(input_chars, output_chars):
    total_chars = input_chars + output_chars
    return (total_chars / 10000.0) * OCI_PRICE_PER_10K_CHARS

def process_file(file_path, treatment):
    try:
        valid_mods = 0
        syntax_errors = 0
        loc_churn = 0
        file_input_chars = 0
        file_output_chars = 0
        file_duration = 0.0
        
        processed_functions = set()
        
        while True:
            with open(file_path, 'rb') as f:
                code_bytes = bytearray(f.read())
                
            tree = parser.parse(bytes(code_bytes))
            initial_errors = count_syntax_errors(tree)
                
            functions = extract_functions(code_bytes)
            if not functions: break
                
            functions.sort(key=lambda x: x[2])
            modification_made_in_this_pass = False
            
            for start, end, _ in functions:
                func_bytes = code_bytes[start:end]
                func_text = func_bytes.decode('utf-8', errors='ignore')
                
                func_hash = hash(func_text)
                if func_hash in processed_functions: continue
                processed_functions.add(func_hash)
                
                system_prompt = PROMPT_RAG if treatment == "llm-rag" else PROMPT_RAW
                user_content = f"CODE TO FIX:\n{func_text}"
                
                if treatment == "llm-rag":
                    context = "" # TODO: RAG Context
                    if context:
                        user_content = f"VULNERABILITY CONTEXT:\n{context}\n\n{user_content}"

                start_time = time.time()
                llm_response = oci_bot.generate_completion(system_prompt, user_content)
                file_duration += (time.time() - start_time)
                
                if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                    new_code_text = llm_response["text"]
                    file_input_chars += llm_response.get("input_chars", 0)
                    file_output_chars += llm_response.get("output_chars", 0)
                    
                    cleaned_code = clean_llm_response(new_code_text, func_text)
                    
                    if cleaned_code != func_text.strip():
                        new_bytes = cleaned_code.encode('utf-8')
                        
                        # Testa a modificação na memória primeiro
                        temp_bytes = bytearray(code_bytes)
                        temp_bytes[start:end] = new_bytes
                        temp_tree = parser.parse(bytes(temp_bytes))
                        new_errors = count_syntax_errors(temp_tree)
                        
                        if new_errors > initial_errors:
                            # O LLM quebrou a sintaxe. Rejeita a modificação.
                            syntax_errors += 1
                            continue # Vai para a próxima função sem salvar
                            
                        # Modificação válida
                        code_bytes = temp_bytes
                        
                        with open(file_path, 'wb') as f_out:
                            f_out.write(code_bytes)
                            
                        # Calcula a diferença de linhas (LOC Churn)
                        old_loc = len(func_text.splitlines())
                        new_loc = len(cleaned_code.splitlines())
                        loc_churn += abs(new_loc - old_loc)
                            
                        valid_mods += 1
                        modification_made_in_this_pass = True
                        break 
                        
            if not modification_made_in_this_pass: break
                
        return valid_mods, syntax_errors, loc_churn, file_input_chars, file_output_chars, file_duration

    except Exception as e:
        print(f"⚠️  Error processing file {file_path}: {e}")
        return 0, 0, 0, 0, 0, 0.0

def run_iteration(treatment, i):
    run_id = f"{treatment}-{i+1}"
    print(f"\n🚀 [Run ID: {run_id}] Starting iteration {i+1}/{NUM_ITERATIONS}...")
    
    dest_path = os.path.join(OUTPUT_DIR, run_id)
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
    
    print(f"📂 Cloning target to: {dest_path}")
    shutil.copytree(BASE_REPO, dest_path, 
                    ignore=shutil.ignore_patterns('node_modules', '.git', 'dist', '.angular', 'tmp', 'vagrant'))
    
    files_to_process = []
    print("🔍 Scanning for target files...")
    target_dirs_paths = [Path(dest_path) / d for d in TARGET_DIRS]

    for root, dirs, files in os.walk(dest_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        current_root = Path(root)
        if any(str(current_root).startswith(str(t_dir)) for t_dir in target_dirs_paths):
            for file in files:
                if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                    files_to_process.append(os.path.join(root, file))

    print("🤖 Refactoring code with Oracle Cloud GenAI...")
    tot_valid = 0
    tot_syntax_err = 0
    tot_loc_churn = 0
    tot_in_chars = 0
    tot_out_chars = 0
    tot_time = 0.0
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(process_file, f, treatment) for f in files_to_process]
        for future in tqdm(futures, total=len(files_to_process), desc=f"Processing {run_id}"):
            v_mods, s_errs, l_churn, in_c, out_c, duration = future.result()
            tot_valid += v_mods
            tot_syntax_err += s_errs
            tot_loc_churn += l_churn
            tot_in_chars += in_c
            tot_out_chars += out_c
            tot_time += duration
            
    run_cost = calculate_cost_oci(tot_in_chars, tot_out_chars)
    estimated_tokens = (tot_in_chars + tot_out_chars) // 4
            
    print(f"✅ Refactoring complete.")
    print(f"📈 Patches Valid: {tot_valid} | Syntax Errors Rejected: {tot_syntax_err} | LOC Churn: {tot_loc_churn}")
    print(f"💸 Cost: ${run_cost:.4f} | Time: {tot_time:.2f} sec")

    print(f"🛡️  Starting CodeQL Security Scan for {run_id}...")
    report_path = os.path.join(OUTPUT_DIR, "reports", run_id)
    scan_result = codeql_scanner.run_scan(dest_path, report_path)
    bug_count = scan_result.get("total", "Error")
    
    print(f"📊 FINAL RESULT [{run_id}]: {bug_count} vulnerabilities detected.")
    
    # Atualizando a gravação do CSV
    with open(os.path.join(OUTPUT_DIR, "experiment_summary.csv"), "a") as summary_file:
        summary_file.write(f"{run_id},{tot_valid},{tot_syntax_err},{tot_loc_churn},{bug_count},{tot_in_chars},{tot_out_chars},{tot_time:.2f},{run_cost:.4f},{estimated_tokens}\n")

def main():
    if not os.path.exists(BASE_REPO):
        print(f"❌ Error: Base repository {BASE_REPO} not found. Run setup_final.sh first.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "reports"), exist_ok=True)
    
    if not os.path.exists(os.path.join(OUTPUT_DIR, "experiment_summary.csv")):
        with open(os.path.join(OUTPUT_DIR, "experiment_summary.csv"), "w") as f:
            f.write("Run_ID,Valid_Patches,Syntax_Errors_Rejected,LOC_Churn,Vulnerabilities_Found,Input_Chars,Output_Chars,Total_Time_Sec,Cost_USD,Estimated_Total_Tokens\n")

    treatments = ["llm-raw", "llm-rag"] 
    
    for treatment in treatments:
        for i in range(NUM_ITERATIONS):
            run_iteration(treatment, i)

if __name__ == "__main__":
    main()