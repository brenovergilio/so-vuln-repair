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

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATION ---
BASE_REPO = "./juice-shop"
OUTPUT_DIR = "./experiment_results/juice-shop"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 3))

# Files to analyze
TARGET_EXTENSIONS = {".ts"}
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
Using the provided CONTEXT about vulnerabilities, refactor the provided JavaScript/TypeScript function to fix any potential security vulnerabilities.
RULES:
1. KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
2. RETURN ONLY THE CODE. No markdown, no explanation.
3. If the code is safe, return it exactly as is.
4. Use the CONTEXT to apply specific fixes.
"""

# --- TREE-SITTER SETUP ---
language = get_language('typescript')
parser = get_parser('typescript')

try:
    oci_bot = OCIClient()
except Exception as e:
    print(f"❌ FATAL: Could not initialize OCI Client. Check .env file. Error: {e}")
    exit(1)

def count_syntax_errors(tree):
    query = language.query("(ERROR) @err")
    return len(query.captures(tree.root_node))

def extract_functions(code_bytes):
    tree = parser.parse(code_bytes)
    query_scm = """
    (function_declaration) @func
    (function_expression) @func
    (arrow_function) @func
    (method_definition) @func
    """
    funcs = []
    for node, _ in language.query(query_scm).captures(tree.root_node):
        funcs.append((node.start_byte, node.end_byte, node.end_byte - node.start_byte))
    return funcs

def clean_llm_response(response, original_code):
    if not response: return original_code
    match = re.search(r'```(?:javascript|typescript|js|ts)?\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else response.strip()

def calculate_cost_oci(input_chars, output_chars):
    return ((input_chars + output_chars) / 10000.0) * OCI_PRICE_PER_10K_CHARS

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
            with open(file_path, 'rb') as f: code_bytes = bytearray(f.read())
            tree = parser.parse(bytes(code_bytes))
            initial_errors = count_syntax_errors(tree)
                
            functions = extract_functions(code_bytes)
            if not functions: break
                
            functions.sort(key=lambda x: x[2])
            modification_made_in_this_pass = False
            
            for start, end, _ in functions:
                func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
                
                func_hash = hash(func_text)
                if func_hash in processed_functions: continue
                processed_functions.add(func_hash)
                
                system_prompt = PROMPT_RAG if treatment == "llm-rag" else PROMPT_RAW
                user_content = f"CODE TO FIX:\n{func_text}"
                
                if treatment == "llm-rag":
                    context = "" # TODO: RAG Context
                    if context: user_content = f"VULNERABILITY CONTEXT:\n{context}\n\n{user_content}"

                start_time = time.time()
                llm_response = oci_bot.generate_completion(system_prompt, user_content)
                file_duration += (time.time() - start_time)
                
                if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                    file_input_chars += llm_response.get("input_chars", 0)
                    file_output_chars += llm_response.get("output_chars", 0)
                    cleaned_code = clean_llm_response(llm_response["text"], func_text)
                    
                    if cleaned_code != func_text.strip():
                        new_bytes = cleaned_code.encode('utf-8')
                        temp_bytes = bytearray(code_bytes)
                        temp_bytes[start:end] = new_bytes
                        
                        if count_syntax_errors(parser.parse(bytes(temp_bytes))) > initial_errors:
                            syntax_errors += 1
                            continue 
                            
                        with open(file_path, 'wb') as f_out: f_out.write(temp_bytes)
                            
                        loc_churn += abs(len(cleaned_code.splitlines()) - len(func_text.splitlines()))
                        valid_mods += 1
                        modification_made_in_this_pass = True
                        break 
                        
            if not modification_made_in_this_pass: break
                
        return valid_mods, syntax_errors, loc_churn, file_input_chars, file_output_chars, file_duration

    except Exception as e:
        print(f"⚠️  Error in {file_path}: {e}")
        return 0, 0, 0, 0, 0, 0.0

def run_iteration(treatment, i):
    run_id = f"{treatment}-{i+1}"
    print(f"\n🚀 [ID: {run_id}] LLM Generation Phase ({i+1}/{NUM_ITERATIONS})...")
    
    dest_path = os.path.join(OUTPUT_DIR, run_id)
    if os.path.exists(dest_path): shutil.rmtree(dest_path)
    shutil.copytree(BASE_REPO, dest_path, ignore=shutil.ignore_patterns('node_modules', '.git', 'dist', '.angular', 'tmp', 'vagrant'))
    
    files_to_process = []
    target_dirs_paths = [Path(dest_path) / d for d in TARGET_DIRS]

    for root, dirs, files in os.walk(dest_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        if any(str(Path(root)).startswith(str(t)) for t in target_dirs_paths):
            files_to_process.extend([os.path.join(root, f) for f in files if any(f.endswith(ext) for ext in TARGET_EXTENSIONS)])

    tot_valid = tot_syntax_err = tot_loc_churn = tot_in_chars = tot_out_chars = 0
    tot_time = 0.0
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        for v, s, l, in_c, out_c, dur in tqdm(executor.map(lambda f: process_file(f, treatment), files_to_process), total=len(files_to_process), desc=f"Refactoring"):
            tot_valid += v; tot_syntax_err += s; tot_loc_churn += l
            tot_in_chars += in_c; tot_out_chars += out_c; tot_time += dur
            
    run_cost = calculate_cost_oci(tot_in_chars, tot_out_chars)
    estimated_tokens = (tot_in_chars + tot_out_chars) // 4
            
    print(f"✅ LLM Phase Complete. Patches: {tot_valid} | Cost: ${run_cost:.4f} | Time: {tot_time:.2f}s")

    with open(os.path.join(OUTPUT_DIR, "llm_metrics.csv"), "a") as f:
        f.write(f"{run_id},{tot_valid},{tot_syntax_err},{tot_loc_churn},{tot_in_chars},{tot_out_chars},{tot_time:.2f},{run_cost:.4f},{estimated_tokens}\n")

def main():
    if not os.path.exists(BASE_REPO): return print(f"❌ Error: {BASE_REPO} not found.")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    csv_path = os.path.join(OUTPUT_DIR, "run_metrics.csv")
    if not os.path.exists(csv_path):
        with open(csv_path, "w") as f: f.write("Run_ID,Valid_Patches,Syntax_Errors_Rejected,LOC_Churn,Input_Chars,Output_Chars,Total_Time_Sec,Cost_USD,Estimated_Total_Tokens\n")

    for treatment in ["llm-raw"]: # ["llm-raw", "llm-rag"]
        for i in range(NUM_ITERATIONS): run_iteration(treatment, i)

if __name__ == "__main__":
    main()