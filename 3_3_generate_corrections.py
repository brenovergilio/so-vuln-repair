import os
import time
import sys
import shutil
import traceback
import json
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from dotenv import load_dotenv
from llm_client import LLMClient
from utils import get_llama_tokenizer, count_llama_tokens, get_dirs_and_extensions, count_syntax_errors, sanitize_code_semantics, extract_functions, extract_graph_context, clean_llm_response, calculate_cost_oci, get_ts_tree_sitter_language_and_parser, get_func_id

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATION ---
BASE_REPO = "./juice-shop"
PROVIDER = os.getenv("PROVIDER", "local")
OUTPUT_DIR = f"./experiment_results/{PROVIDER}/juice-shop"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 3))
TREATMENTS = [ "llm-raw", "llm-rag", "llm-graph-compressed-rag"] # "llm-raw" , "llm-graph-compressed-rag"

TARGET_EXTENSIONS, IGNORE_EXTENSIONS, TARGET_DIRS, IGNORE_DIRS, IGNORE_FILES = get_dirs_and_extensions()

COMPRESSED_JSON_PATH = "./compressed_contexts.json"
RAW_JSON_PATH = "./raw_so_contexts.json"

# Variáveis separadas para carregar os conteúdos
compressed_contexts = {}
raw_contexts = {}

# 1. Verifica e carrega para o tratamento COM compressão
if "llm-graph-compressed-rag" in TREATMENTS:
    if os.path.exists(COMPRESSED_JSON_PATH):
        print(f"📦 Carregando RAG comprimido de: {COMPRESSED_JSON_PATH}")
        with open(COMPRESSED_JSON_PATH, "r", encoding="utf-8") as f:
            compressed_contexts = json.load(f)
    else:
        print(f"❌ ERRO FATAL: O tratamento 'llm-graph-compressed-rag' foi selecionado, mas o arquivo {COMPRESSED_JSON_PATH} não existe. Abortando.")
        sys.exit(1)

# 2. Verifica e carrega para o tratamento SEM compressão (SOSecure original)
if "llm-rag" in TREATMENTS:
    if os.path.exists(RAW_JSON_PATH):
        print(f"📦 Carregando RAG bruto de: {RAW_JSON_PATH}")
        with open(RAW_JSON_PATH, "r", encoding="utf-8") as f:
            raw_contexts = json.load(f)
    else:
        print(f"❌ ERRO FATAL: O tratamento 'llm-rag' foi selecionado, mas o arquivo {RAW_JSON_PATH} não existe. Abortando.")
        sys.exit(1)

# =====================================================================
# --- SOSECURE REPLICATION PROMPTS ---
# =====================================================================
PROMPT_SYS = "You are a helpful assistant that generates secure JavaScript/TypeScript code. Please provide all generated code in one code block."

def get_prompt_raw(query):
    return f"""Given the following code:

{query}

**Instructions:**
- Review the code for potential security flaws.
- If security issues are found, modify the code minimally to fix the issue while maintaining its original functionality and logic.
- If no security issues are found, output "No security issues found".
- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
- RETURN ONLY THE CODE. No markdown, no explanation.
"""

def get_prompt_rag(query, context):
    return f"""Given the following code:

{query}

Does this code have any security vulnerabilities? Below is a related StackOverflow additional context that may be helpful:
---
{context}
---

**Instructions:**
- Review the code for any security flaws.
- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.
- If no security issues are found, output "No security issues found".
- Ensure that the fixes do not alter the original intent of the code.
- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
- RETURN ONLY THE CODE. No markdown, no explanation.
- It is imperative that the new code should not have any CWE or CVE security errors.
"""

# --- TOKENIZER SETUP ---
tokenizer = get_llama_tokenizer()
print("✅ Tokenizer loaded.")

# --- TREE-SITTER SETUP ---
language, parser = get_ts_tree_sitter_language_and_parser()

try:
    llm_client = LLMClient(provider=PROVIDER)
except Exception as e:
    print(f"❌ FATAL: Could not initialize LLM Client. Check .env file. Error: {e}")
    exit(1)

def process_file(file_path, treatment, run_id, dest_path):
    if os.path.basename(file_path) in IGNORE_FILES:
        return 0, 0, 0, 0, 0, 0, 0.0

    try:
        valid_mods = 0
        syntax_errors = 0
        loc_churn = 0
        file_input_tokens = 0
        file_output_tokens = 0
        file_total_chars_for_cost = 0 
        file_duration = 0.0
        processed_functions = set()
        
        max_passes = 30 
        current_pass = 0
        
        while current_pass < max_passes:
            current_pass += 1
            with open(file_path, 'rb') as f: code_bytes = bytearray(f.read())
            tree = parser.parse(bytes(code_bytes))
            initial_errors = count_syntax_errors(tree, language, parser)
                
            functions = extract_functions(code_bytes, language, parser)
            if not functions: break
                
            functions.sort(key=lambda x: x[2])
            modification_made_in_this_pass = False
            
            for func_tuple in functions:
                start = func_tuple[0]
                end = func_tuple[1]
                func_name = func_tuple[3] if len(func_tuple) > 3 else "Unknown_Function"
                
                original_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
                clean_func_text = sanitize_code_semantics(original_func_text, language, parser)
                
                # Usa o MD5 para garantir a exata mesma chave gerada na Fase 1
                func_id = get_func_id(clean_func_text)
                if func_id in processed_functions: continue
                processed_functions.add(func_id)
                
                # --- MONTAGEM BASE DO PROMPT SOSECURE ---
                # --- MONTAGEM BASE DO PROMPT SOSECURE ---
                system_prompt = PROMPT_SYS
                user_content = ""
                
                if treatment == "llm-raw":
                    user_content = get_prompt_raw(clean_func_text)
                    
                else: # Tratamentos baseados em RAG
                    rel_path_key = os.path.relpath(file_path, dest_path)
                    final_rag_context = ""

                    if treatment == "llm-graph-compressed-rag":
                        graph_context_text = extract_graph_context(code_bytes, language, parser)
                        compressed_discussion = compressed_contexts.get(rel_path_key, {}).get(func_id, "")
                        
                        if graph_context_text:
                            final_rag_context += f"[LOCAL IMPORTS/DEPENDENCIES]\n{graph_context_text}\n\n"
                        if compressed_discussion:
                            final_rag_context += f"[COMMUNITY DISCUSSIONS]\n{compressed_discussion}"
                            
                    elif treatment == "llm-rag":
                        final_rag_context = raw_contexts.get(rel_path_key, {}).get(func_id, "")
                        
                    user_content = get_prompt_rag(clean_func_text, final_rag_context)

                full_prompt = system_prompt + "\n" + user_content
                final_response_text = ""
                final_output_tokens_count = 0
                input_tokens_count = count_llama_tokens(full_prompt, tokenizer)
                
                # --- LOOP DE TENTATIVAS PARA O PATCH FINAL ---
                for attempt in range(5):
                    file_input_tokens += input_tokens_count

                    start_time = time.time()
                    llm_response = llm_client.generate_completion(system_prompt, user_content)
                    file_duration += (time.time() - start_time)
                    
                    if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                        response_text = llm_response["text"]
                        final_response_text = response_text
                        
                        final_output_tokens_count = count_llama_tokens(response_text, tokenizer)
                        file_output_tokens += final_output_tokens_count
                        file_total_chars_for_cost += len(full_prompt) + len(response_text)
                        
                        cleaned_code = clean_llm_response(response_text, clean_func_text)
                        
                        if cleaned_code != clean_func_text.strip():
                            new_bytes = cleaned_code.encode('utf-8')
                            temp_bytes = bytearray(code_bytes)
                            temp_bytes[start:end] = new_bytes
                            
                            if count_syntax_errors(parser.parse(bytes(temp_bytes)), language, parser) > initial_errors:
                                syntax_errors += 1
                                continue
                                
                            with open(file_path, 'wb') as f_out: f_out.write(temp_bytes)
                                
                            loc_churn += abs(len(cleaned_code.splitlines()) - len(clean_func_text.splitlines()))
                            valid_mods += 1
                            modification_made_in_this_pass = True
                            break 
                        else:
                            break
                    else:
                        break
                
                # --- REGISTRO DO LOG DO ARQUIVO COM CONTADOR DE TOKENS ---
                log_base_dir = os.path.join(OUTPUT_DIR, f"{run_id}_logs")
                rel_path = os.path.relpath(file_path, dest_path)
                log_file_path = os.path.join(log_base_dir, rel_path + ".txt")
                
                os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
                
                with open(log_file_path, "a", encoding="utf-8") as log_f:
                    log_f.write(f"File Path: {file_path}\n")
                    log_f.write(f"Function: {func_name}\n")
                    log_f.write(f"Input Tokens: {input_tokens_count}\n")
                    log_f.write(f"Output Tokens: {final_output_tokens_count}\n")
                    log_f.write(f"Input:\n{user_content}\n")
                    log_f.write(f"Output:\n{final_response_text}\n")
                    log_f.write("=========================\n")

                if modification_made_in_this_pass:
                    break 
                        
            if not modification_made_in_this_pass: break
                
        return valid_mods, syntax_errors, loc_churn, file_input_tokens, file_output_tokens, file_total_chars_for_cost, file_duration

    except Exception as e:
        print(f"⚠️  Error in {file_path}: {e}")
        return 0, 0, 0, 0, 0, 0, 0.0

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
            files_to_process.extend([
                os.path.join(root, f) for f in files 
                if any(f.endswith(ext) for ext in TARGET_EXTENSIONS) 
                and not any(f.endswith(ext) for ext in IGNORE_EXTENSIONS)
            ])

    tot_valid = tot_syntax_err = tot_loc_churn = tot_in_tokens = tot_out_tokens = tot_chars_for_cost = 0
    tot_time = 0.0
    
    # max_workers=1 OBRIGATÓRIO SE RODAR TUDO NO MESMO NÓ PARA NÃO ESTOURAR O KV CACHE
    with ThreadPoolExecutor(max_workers=1) as executor:
        for v, s, l, in_t, out_t, t_chars, dur in tqdm(executor.map(lambda f: process_file(f, treatment, run_id, dest_path), files_to_process), total=len(files_to_process), desc=f"Refactoring"):
            tot_valid += v; tot_syntax_err += s; tot_loc_churn += l
            tot_in_tokens += in_t; tot_out_tokens += out_t; tot_chars_for_cost += t_chars
            tot_time += dur
            
    run_cost = calculate_cost_oci(tot_chars_for_cost)
            
    print(f"✅ LLM Phase Complete. Patches: {tot_valid} | Cost: ${run_cost:.4f} | Time: {tot_time:.2f}s")
    print(f"📊 Exact Tokens: {tot_in_tokens} (Input) + {tot_out_tokens} (Output) = {tot_in_tokens + tot_out_tokens} Total")

    with open(os.path.join(OUTPUT_DIR, "llm_metrics.csv"), "a") as f:
        f.write(f"{run_id},{tot_valid},{tot_syntax_err},{tot_loc_churn},{tot_in_tokens},{tot_out_tokens},{tot_time:.2f},{run_cost:.4f}\n")

def main():
    if not os.path.exists(BASE_REPO): return print(f"❌ Error: {BASE_REPO} not found.")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    csv_path = os.path.join(OUTPUT_DIR, "llm_metrics.csv")
    if not os.path.exists(csv_path):
        with open(csv_path, "w") as f: f.write("Run_ID,Valid_Patches,Syntax_Errors_Rejected,LOC_Churn,Input_Tokens,Output_Tokens,Total_Time_Sec,Cost_USD\n")

    for treatment in TREATMENTS:
        for i in range(NUM_ITERATIONS): 
            run_iteration(treatment, i)

if __name__ == "__main__":
    main()