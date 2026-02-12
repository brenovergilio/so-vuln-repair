import os
import shutil
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
OUTPUT_DIR = "./experiment_results"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 5))

# Files to analyze
TARGET_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}
# Important directories in Juice Shop
TARGET_DIRS = {"routes", "lib", "models", "data", "frontend/src/app"} 
# Directories to ignore
IGNORE_DIRS = {"node_modules", ".git", "test", "dist", ".angular", "e2e", "vagrant"}

# --- SYSTEM PROMPTS (ENGLISH) ---
PROMPT_RAW = """You are a Secure Code Assistant. 
Refactor the provided JavaScript/TypeScript function to fix any potential security vulnerabilities (SQL Injection, XSS, Path Traversal, etc).
RULES:
1. KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments and name).
2. RETURN ONLY THE CODE. No markdown, no explanation.
3. If the code is safe, return it exactly as is.
"""

PROMPT_RAG = """You are a Secure Code Assistant equipped with vulnerability knowledge.
Using the provided CONTEXT about known vulnerabilities in this project, refactor the function to be secure.
RULES:
1. KEEP THE EXACT SAME FUNCTION SIGNATURE.
2. RETURN ONLY THE CODE. No markdown.
3. If the code is safe, return it exactly as is.
4. Use the context to apply specific fixes.
"""

# --- TREE-SITTER SETUP ---
# We use the generic javascript parser which handles most TS syntax for function extraction
language = get_language('javascript')
parser = get_parser('javascript')

# Initialize OCI Client
try:
    oci_bot = OCIClient()
except Exception as e:
    print(f"❌ FATAL: Could not initialize OCI Client. Check .env file. Error: {e}")
    exit(1)

def extract_functions(code_bytes):
    """
    Parses the code using Tree-Sitter AST and extracts function ranges.
    Returns a list of tuples: (start_byte, end_byte, function_content_bytes)
    """
    tree = parser.parse(code_bytes)
    
    # S-Expression Query to find all types of functions in JS/TS
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
        # We capture the full byte range of the function
        funcs.append((node.start_byte, node.end_byte, code_bytes[node.start_byte:node.end_byte]))
        
    return funcs

def clean_llm_response(response, original_code):
    """Clean markdown formatting from LLM response"""
    if not response: 
        return original_code
        
    cleaned = response
    if "```" in response:
        lines = response.split('\n')
        # Filter out lines starting with ``` (e.g., ```javascript)
        clean_lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(clean_lines)
    
    return cleaned

def process_file(file_path, treatment):
    """
    1. Reads file
    2. Extracts functions
    3. Sends to LLM
    4. Replaces code in-place
    """
    try:
        with open(file_path, 'rb') as f:
            code_bytes = f.read()
            
        functions = extract_functions(code_bytes)
        
        if not functions:
            return 0
            
        # CRITICAL: Sort functions in reverse order (bottom-up).
        # This prevents byte offsets from shifting when we replace code at the top.
        functions.sort(key=lambda x: x[0], reverse=True)
        
        new_code_bytes = bytearray(code_bytes)
        modified_count = 0
        
        for start, end, func_bytes in functions:
            func_text = func_bytes.decode('utf-8', errors='ignore')
            
            # Skip very small (one-liners) or huge functions (context limit)
            #if len(func_text) < 50 or len(func_text) > 4000:
            #    continue
            
            # Prepare Prompt
            system_prompt = PROMPT_RAG if treatment == "llm-rag" else PROMPT_RAW
            user_content = f"CODE TO FIX:\n{func_text}"
            
            if treatment == "llm-rag":
                # TODO: Integrate Qdrant/RAG retrieval here
                context = "" 
                if context:
                    user_content = f"VULNERABILITY CONTEXT:\n{context}\n\n{user_content}"

            # Call Oracle Cloud
            new_code_text = oci_bot.generate_completion(system_prompt, user_content)
            
            if new_code_text:
                cleaned_code = clean_llm_response(new_code_text, func_text)
                
                # Encode back to bytes and replace in the bytearray
                new_bytes = cleaned_code.encode('utf-8')
                
                # The actual replacement logic
                new_code_bytes[start:end] = new_bytes
                modified_count += 1
                
        # Only write back if changes occurred
        if modified_count > 0:
            with open(file_path, 'wb') as f:
                f.write(new_code_bytes)
                
        return modified_count

    except Exception as e:
        print(f"⚠️  Error processing file {file_path}: {e}")
        return 0

def run_iteration(treatment, i):
    run_id = f"{treatment}-{i+1}"
    print(f"\n🚀 [Run ID: {run_id}] Starting iteration {i+1}/{NUM_ITERATIONS}...")
    
    # 1. Setup Environment (Copy Folder)
    dest_path = os.path.join(OUTPUT_DIR, run_id)
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
    
    print(f"📂 Cloning target to: {dest_path}")
    shutil.copytree(BASE_REPO, dest_path, 
                    ignore=shutil.ignore_patterns('node_modules', '.git', 'dist', '.angular', 'tmp', 'vagrant'))
    
    # 2. Map Files
    files_to_process = []
    print("🔍 Scanning for target files...")
    
    for root, dirs, files in os.walk(dest_path):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                rel_path = os.path.relpath(os.path.join(root, file), dest_path)
                # Check if file is inside a target directory (backend or frontend)
                if any(target in rel_path for target in TARGET_DIRS):
                    files_to_process.append(os.path.join(root, file))

    print(f"📋 Found {len(files_to_process)} files to analyze.")

    # 3. Process with LLM
    print("🤖 Refactoring code with Oracle Cloud GenAI...")
    total_modifications = 0
    
    # Max workers limited to avoid OCI Rate Limits (429)
    with ThreadPoolExecutor(max_workers=2) as executor:
        # Submit all tasks
        futures = [executor.submit(process_file, f, treatment) for f in files_to_process]
        
        # Monitor progress
        for future in tqdm(futures, total=len(files_to_process), desc=f"Processing {run_id}"):
            total_modifications += future.result()
            
    print(f"✅ Refactoring complete. Total functions rewritten: {total_modifications}")

    # 4. Run Security Audit (CodeQL)
    print(f"🛡️  Starting CodeQL Security Scan for {run_id}...")
    report_path = os.path.join(OUTPUT_DIR, "reports", run_id)
    
    scan_result = codeql_scanner.run_scan(dest_path, report_path)
    
    bug_count = scan_result.get("total", "Error")
    print(f"📊 FINAL RESULT [{run_id}]: {bug_count} vulnerabilities detected.")
    
    # Optional: Save stats to a CSV summary
    with open(os.path.join(OUTPUT_DIR, "experiment_summary.csv"), "a") as summary_file:
        summary_file.write(f"{run_id},{total_modifications},{bug_count}\n")

def main():
    if not os.path.exists(BASE_REPO):
        print(f"❌ Error: Base repository {BASE_REPO} not found. Run setup_final.sh first.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "reports"), exist_ok=True)
    
    # Initialize summary CSV
    if not os.path.exists(os.path.join(OUTPUT_DIR, "experiment_summary.csv")):
        with open(os.path.join(OUTPUT_DIR, "experiment_summary.csv"), "w") as f:
            f.write("Run_ID,Functions_Rewritten,Vulnerabilities_Found\n")

    # Define treatments
    # treatments = ["llm-raw", "llm-rag"]
    treatments = ["llm-raw"] # Start simple
    
    for treatment in treatments:
        for i in range(NUM_ITERATIONS):
            run_iteration(treatment, i)

if __name__ == "__main__":
    main()