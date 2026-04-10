import os
import time
import sys
import shutil
import json
import subprocess
import requests
import atexit
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from dotenv import load_dotenv
from llm_client import LLMClient
from utils import (
    get_llama_tokenizer, count_llama_tokens, get_dirs_and_extensions, 
    sanitize_code_semantics, extract_functions, 
    clean_llm_response, calculate_cost_oci, get_ts_tree_sitter_language_and_parser, 
    get_func_id, get_type_aware_context, run_tsc_check
)

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATION ---
BASE_REPO = "./juice-shop"
PROVIDER = os.getenv("PROVIDER", "local")
OUTPUT_DIR = f"./experiment_results/{PROVIDER}/juice-shop"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 3))
# FIX: max_workers parametrizável via env; padrão 1 mantido para reprodutibilidade,
#      mas agora pode ser aumentado sem alterar o código
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 1))
TREATMENTS = ["posecure-extractive", "posecure-abstractive", "cvefixes"] # "llm-raw", "sosecure", "posecure-extractive", "posecure-abstractive", "cvefixes"

TARGET_EXTENSIONS, IGNORE_EXTENSIONS, TARGET_DIRS, IGNORE_DIRS, IGNORE_FILES = get_dirs_and_extensions()

COMPRESSED_JSON_PATH = "./compressed_contexts.json"
RAW_JSON_PATH = "./raw_so_contexts.json"
ABSTRACTIVE_JSON_PATH = "./abstractive_contexts.json"
CVEFIXES_JSON_PATH = "./cvefixes_contexts.json"

# =====================================================================
# --- TYPE-EXTRACTOR SERVER ORCHESTRATION ---
# =====================================================================
node_server_process = None

def cleanup_node_server():
    global node_server_process
    if node_server_process:
        print("\n🧹 [TEARDOWN] Desligando o Type-Extractor Server (Porta 3001)...")
        node_server_process.terminate()
        try:
            node_server_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            node_server_process.kill()
        subprocess.run(["fuser", "-k", "-s", "9", "3001/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("   ✅ Servidor Node.js encerrado.")

def start_type_extractor_server():
    global node_server_process
    print("\n⚙️  [SETUP] Verificando necessidade do Type-Extractor Server...")

    extractor_dir = "./type-extractor"
    if not os.path.exists(extractor_dir):
        print(f"❌ ERRO FATAL: O diretório '{extractor_dir}' não foi encontrado.")
        sys.exit(1)

    print("   🚀 Iniciando o Bi-directional RAG Extractor (Node.js) em background...")
    subprocess.run(["fuser", "-k", "-s", "9", "3001/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    node_server_process = subprocess.Popen(
        ["node", "server.js"], 
        cwd=extractor_dir,
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL
    )

    print("   ⏳ Aguardando servidor Node.js responder na porta 3001...")
    server_ready = False
    for _ in range(15):
        try:
            resp = requests.get("http://localhost:3001", timeout=1)
            server_ready = True
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            print(".", end="", flush=True)
            
    if server_ready:
        print("\n   ✅ Type-Extractor Server Online e pronto para uso!")
    else:
        print("\n❌ ERRO FATAL: O servidor Node.js não respondeu a tempo. Abortando.")
        cleanup_node_server()
        sys.exit(1)

atexit.register(cleanup_node_server)
# FIX: start_type_extractor_server() movido para dentro de main() para
#      evitar side-effect no import/nível de módulo

# Variáveis separadas para carregar os conteúdos
compressed_contexts = {}
raw_contexts = {}
abstractive_contexts = {}
cvefixes_contexts = {}

# =====================================================================
# --- SOSECURE REPLICATION PROMPTS ---
# =====================================================================
PROMPT_SYS = "You are a helpful assistant that generates secure JavaScript/TypeScript code. Please provide all generated code in one code block."

def get_prompt_raw(query, type_signatures=""):
    type_block = f"\nBelow are the EXACT type signatures and contracts for the libraries and local modules imported in this file. \nSTRICTLY ADHERE to these definitions to prevent compilation errors. Do not hallucinate parameters or methods that do not exist in these signatures:\n---\n{type_signatures}\n---\n" if type_signatures.strip() else ""
    return f"""Given the following code:\n\n{query}\n{type_block}**Instructions:**\n- Review the code for potential security flaws.\n- If security issues are found, modify the code minimally to fix the issue while maintaining its original functionality and logic.\n- If no security issues are found, output "No security issues found".\n- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).\n- RETURN ONLY THE CODE. No markdown, no explanation.\n\n**STRICT COMPILATION & FRAMEWORK RULES (CRITICAL):**\n1. NO NEW IMPORTS: You are modifying an isolated function block. DO NOT invoke external libraries (like DOMPurify, Joi, xss, etc.) or RxJS operators (`of`, `throwError`) unless they are ALREADY defined in the [LIBRARY SIGNATURES]. \n2. CLASS METHOD PRESERVATION: If the provided code is a class method (e.g., `methodName(...) {{ ... }}`), return it EXACTLY as a class method. DO NOT prepend the `function` keyword or convert it to an arrow function property.\n3. TYPESCRIPT STRICT ERRORS: In `catch (error)` blocks, assume `error` is of type `unknown`. You MUST typecast it (e.g., `if (error instanceof Error) {{ ... }}`) before accessing properties like `.message`.\n4. NO MODERN ES2022 ERROR CAUSES: DO NOT use the {{ cause: error }} object when instantiating Errors (e.g., do not write `new Error(msg, {{ cause: err }})`). Strictly use the standard `new Error(msg)`.\n5. STRICT TYPE PRESERVATION: Do not change the original nullability of variables or return types. Do not reassign variables declared with `const`.\n6. ANGULAR SANITIZER AWARENESS: If you use Angular's `this.sanitizer.sanitize()`, it strictly requires TWO arguments (SecurityContext and the value). If context is unavailable, use standard JS regex/type-checking to prevent XSS.\n7. ENVIRONMENT ISOLATION: Do not mix browser modules with Node.js modules. If the code uses Angular injections (like `this.router`), DO NOT use Node.js native modules like `crypto.createHash()`.\n8. MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.\n"""

def get_prompt_rag(query, context, type_signatures=""):
    type_block = f"\nBelow are the EXACT type signatures and contracts for the libraries and local modules imported in this file. \nSTRICTLY ADHERE to these definitions to prevent compilation errors. Do not hallucinate parameters or methods that do not exist in these signatures:\n---\n{type_signatures}\n---\n" if type_signatures.strip() else ""
    return f"""Given the following code:\n\n{query}\n{type_block}\nDoes this code have any security vulnerabilities? Below is a related StackOverflow additional context that may be helpful:\n---\n{context}\n---\n\n**Instructions:**\n- Review the code for any security flaws.\n- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.\n- If no security issues are found, output "No security issues found".\n- Ensure that the fixes do not alter the original intent of the code.\n- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).\n- RETURN ONLY THE CODE. No markdown, no explanation.\n- It is imperative that the new code should not have any CWE or CVE security errors.\n\n**STRICT COMPILATION & FRAMEWORK RULES (CRITICAL):**\n1. NO NEW IMPORTS: You are modifying an isolated function block. DO NOT invoke external libraries (like DOMPurify, Joi, xss, etc.) or RxJS operators (`of`, `throwError`) unless they are ALREADY defined in the [LIBRARY SIGNATURES]. \n2. CLASS METHOD PRESERVATION: If the provided code is a class method (e.g., `methodName(...) {{ ... }}`), return it EXACTLY as a class method. DO NOT prepend the `function` keyword or convert it to an arrow function property.\n3. TYPESCRIPT STRICT ERRORS: In `catch (error)` blocks, assume `error` is of type `unknown`. You MUST typecast it (e.g., `if (error instanceof Error) {{ ... }}`) before accessing properties like `.message`.\n4. NO MODERN ES2022 ERROR CAUSES: DO NOT use the {{ cause: error }} object when instantiating Errors (e.g., do not write `new Error(msg, {{ cause: err }})`). Strictly use the standard `new Error(msg)`.\n5. STRICT TYPE PRESERVATION: Do not change the original nullability of variables or return types. Do not reassign variables declared with `const`.\n6. ANGULAR SANITIZER AWARENESS: If you use Angular's `this.sanitizer.sanitize()`, it strictly requires TWO arguments (SecurityContext and the value). If context is unavailable, use standard JS regex/type-checking to prevent XSS.\n7. ENVIRONMENT ISOLATION: Do not mix browser modules with Node.js modules. If the code uses Angular injections (like `this.router`), DO NOT use Node.js native modules like `crypto.createHash()`.\n8. MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.\n"""

def get_prompt_posecure(query, context, type_signatures=""):
    type_block = f"\nBelow are the EXACT type signatures and contracts for the libraries and local modules imported in this file. \nSTRICTLY ADHERE to these definitions to prevent compilation errors. Do not hallucinate parameters or methods that do not exist in these signatures:\n---\n{type_signatures}\n---\n" if type_signatures.strip() else ""
    context_block = f"Below is a related StackOverflow additional context that may be helpful:\n---\n{context}\n---\n" if context.strip() else ""
    return f"""Given the following code:\n\n{query}\n\nDoes this code have any security vulnerabilities? \n{context_block}\n{type_block}**Instructions:**\n- Review the code for any security flaws.\n- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.\n- If no security issues are found, output "No security issues found".\n- Ensure that the fixes do not alter the original intent of the code.\n- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).\n- MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.\n- RETURN ONLY THE CODE. No markdown, no explanation.\n- It is imperative that the new code should not have any CWE or CVE security errors.\n\n**STRICT COMPILATION & FRAMEWORK RULES (CRITICAL):**\n1. NO NEW IMPORTS: You are modifying an isolated function block. DO NOT invoke external libraries (like DOMPurify, Joi, xss, etc.) or RxJS operators (`of`, `throwError`) unless they are ALREADY defined in the [LIBRARY SIGNATURES]. \n2. CLASS METHOD PRESERVATION: If the provided code is a class method (e.g., `methodName(...) {{ ... }}`), return it EXACTLY as a class method. DO NOT prepend the `function` keyword or convert it to an arrow function property.\n3. TYPESCRIPT STRICT ERRORS: In `catch (error)` blocks, assume `error` is of type `unknown`. You MUST typecast it (e.g., `if (error instanceof Error) {{ ... }}`) before accessing properties like `.message`.\n4. NO MODERN ES2022 ERROR CAUSES: DO NOT use the {{ cause: error }} object when instantiating Errors (e.g., do not write `new Error(msg, {{ cause: err }})`). Strictly use the standard `new Error(msg)`.\n5. STRICT TYPE PRESERVATION: Do not change the original nullability of variables or return types. Do not reassign variables declared with `const`.\n6. ANGULAR SANITIZER AWARENESS: If you use Angular's `this.sanitizer.sanitize()`, it strictly requires TWO arguments (SecurityContext and the value). If context is unavailable, use standard JS regex/type-checking to prevent XSS.\n7. ENVIRONMENT ISOLATION: Do not mix browser modules with Node.js modules. If the code uses Angular injections (like `this.router`), DO NOT use Node.js native modules like `crypto.createHash()`.\n8. MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.\n"""

def get_prompt_cvefixes(query, context, type_signatures=""):
    type_block = f"\nBelow are the EXACT type signatures and contracts for the libraries and local modules imported in this file. \nSTRICTLY ADHERE to these definitions to prevent compilation errors. Do not hallucinate parameters or methods that do not exist in these signatures:\n---\n{type_signatures}\n---\n" if type_signatures.strip() else ""
    context_block = f"Below are related real-world vulnerability patterns (CVEs) and their secure fixes that may be helpful as a reference for your correction:\n---\n{context}\n---\n" if context.strip() else ""
    return f"""Given the following code:\n\n{query}\n\nDoes this code have any security vulnerabilities? \n{context_block}\n{type_block}**Instructions:**\n- Review the code for any security flaws.\n- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.\n- If no security issues are found, output "No security issues found".\n- Ensure that the fixes do not alter the original intent of the code.\n- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).\n- MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.\n- RETURN ONLY THE CODE. No markdown, no explanation.\n- It is imperative that the new code should not have any CWE or CVE security errors.\n\n**STRICT COMPILATION & FRAMEWORK RULES (CRITICAL):**\n1. NO NEW IMPORTS: You are modifying an isolated function block. DO NOT invoke external libraries (like DOMPurify, Joi, xss, etc.) or RxJS operators (`of`, `throwError`) unless they are ALREADY defined in the [LIBRARY SIGNATURES]. \n2. CLASS METHOD PRESERVATION: If the provided code is a class method (e.g., `methodName(...) {{ ... }}`), return it EXACTLY as a class method. DO NOT prepend the `function` keyword or convert it to an arrow function property.\n3. TYPESCRIPT STRICT ERRORS: In `catch (error)` blocks, assume `error` is of type `unknown`. You MUST typecast it (e.g., `if (error instanceof Error) {{ ... }}`) before accessing properties like `.message`.\n4. NO MODERN ES2022 ERROR CAUSES: DO NOT use the {{ cause: error }} object when instantiating Errors (e.g., do not write `new Error(msg, {{ cause: err }})`). Strictly use the standard `new Error(msg)`.\n5. STRICT TYPE PRESERVATION: Do not change the original nullability of variables or return types. Do not reassign variables declared with `const`.\n6. ANGULAR SANITIZER AWARENESS: If you use Angular's `this.sanitizer.sanitize()`, it strictly requires TWO arguments (SecurityContext and the value). If context is unavailable, use standard JS regex/type-checking to prevent XSS.\n7. ENVIRONMENT ISOLATION: Do not mix browser modules with Node.js modules. If the code uses Angular injections (like `this.router`), DO NOT use Node.js native modules like `crypto.createHash()`.\n8. MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.\n"""

def get_self_healing_prompt(llm_generated_code, build_errors_list):
    """
    Gera o prompt de segunda tentativa (Self-Healing) passando apenas
    o código gerado e os erros do compilador.
    """
    errors_str = "\n".join(build_errors_list)
    
    return f"""You previously generated the following TypeScript code:

```typescript
{llm_generated_code}
```

However, when compiling, it resulted in the following TypeScript build errors:
---
{errors_str}
---

**Instructions:**
- Fix the compilation errors in the code above.
- DO NOT hallucinate new imports or properties. Use only what is available in the scope.
- RETURN ONLY THE CORRECTED CODE. No markdown, no explanation.
- KEEP THE EXACT SAME FUNCTION SIGNATURE.
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
        failed_healings = 0
        loc_churn = 0
        file_input_tokens = 0
        file_output_tokens = 0
        file_total_chars_for_cost = 0 
        file_duration = 0.0
        
        with open(file_path, 'rb') as f: code_bytes = bytearray(f.read())
        tree = parser.parse(bytes(code_bytes))
            
        functions = extract_functions(code_bytes, language, parser)
        if not functions:
            # FIX: tupla de retorno padronizada com 8 valores em todos os caminhos
            return 0, 0, 0, 0, 0, 0, 0.0
            
        functions.sort(key=lambda x: x[0], reverse=True)
        rel_path_key = os.path.relpath(file_path, dest_path)
        
        log_base_dir = os.path.join(OUTPUT_DIR, f"{run_id}_logs")
        os.makedirs(os.path.dirname(os.path.join(log_base_dir, rel_path_key)), exist_ok=True)
        log_file_path = os.path.join(log_base_dir, rel_path_key + ".txt")
        failed_healing_log_path = os.path.join(log_base_dir, "failed_self_healing.log")
        
        for func_tuple in functions:
            start = func_tuple[0]
            end = func_tuple[1]
            func_name = func_tuple[3] if len(func_tuple) > 3 else "Unknown_Function"
            
            original_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
            clean_func_text = sanitize_code_semantics(original_func_text, language, parser)
            func_id = get_func_id(clean_func_text)
            
            system_prompt = PROMPT_SYS
            user_content = ""
            rel_path_to_original = os.path.join(BASE_REPO, rel_path_key)
            type_signatures = get_type_aware_context(os.path.abspath(rel_path_to_original), clean_func_text)
            
            if treatment == "llm-raw":
                user_content = get_prompt_raw(clean_func_text, type_signatures=type_signatures)
            elif treatment == "sosecure":
                final_rag_context = raw_contexts.get(rel_path_key, {}).get(func_id, "")
                user_content = get_prompt_rag(clean_func_text, final_rag_context, type_signatures=type_signatures)
            elif treatment == "posecure-extractive":
                extractive_summary = compressed_contexts.get(rel_path_key, {}).get(func_id, "")
                final_rag_context = f"[COMMUNITY SECURITY DISCUSSIONS]\n{extractive_summary}" if extractive_summary else ""
                user_content = get_prompt_posecure(clean_func_text, final_rag_context, type_signatures)
            elif treatment == "posecure-abstractive":
                abstractive_summary = abstractive_contexts.get(rel_path_key, {}).get(func_id, "")
                final_rag_context = f"[COMMUNITY SECURITY DISCUSSIONS]\n{abstractive_summary}" if abstractive_summary else ""
                user_content = get_prompt_posecure(clean_func_text, final_rag_context, type_signatures)
            elif treatment == "cvefixes":
                cvefixes_examples = cvefixes_contexts.get(rel_path_key, {}).get(func_id, "")
                final_rag_context = f"[KNOWN VULNERABILITY FIXES]\n{cvefixes_examples}" if cvefixes_examples else ""
                user_content = get_prompt_cvefixes(clean_func_text, final_rag_context, type_signatures)

            # --- VARIÁVEIS DE CONTROLE PARA O LOG FINAL DESTA FUNÇÃO ---
            func_in_tokens = count_llama_tokens(system_prompt + "\n" + user_content, tokenizer)
            file_input_tokens += func_in_tokens
            
            func_out_tokens = 0
            patch_status = "Skipped (No changes)"
            
            # String acumuladora para o log final
            func_log_content = f"Function: {func_name}\n"
            func_log_content += f"Input (Pass 1):\n{user_content}\n"
            
            # PRIMEIRA CHAMADA
            start_time = time.time()
            llm_response = llm_client.generate_completion(system_prompt, user_content)
            file_duration += (time.time() - start_time)
            
            if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                response_text = llm_response["text"]
                pass_1_out_tokens = count_llama_tokens(response_text, tokenizer)
                func_out_tokens += pass_1_out_tokens
                file_output_tokens += pass_1_out_tokens
                file_total_chars_for_cost += len(system_prompt + "\n" + user_content) + len(response_text)
                
                func_log_content += f"Output (Pass 1):\n{response_text}\n"

                cleaned_code = clean_llm_response(response_text, clean_func_text)
                
                if cleaned_code != clean_func_text.strip():
                    new_bytes = cleaned_code.encode('utf-8')
                    temp_bytes = bytearray(code_bytes)
                    temp_bytes[start:end] = new_bytes
                    
                    patch_accepted = False

                    # TIER 2: COMPILER FEEDBACK E SELF-HEALING (Ignora o Tree-sitter)
                    with open(file_path, 'wb') as f_out: f_out.write(temp_bytes)
                    
                    build_errors_list, error_count = run_tsc_check(dest_path)
                    
                    if error_count > 0:
                        healing_prompt = get_self_healing_prompt(cleaned_code, build_errors_list)
                        
                        healing_in_tokens = count_llama_tokens(system_prompt + "\n" + healing_prompt, tokenizer)
                        func_in_tokens += healing_in_tokens
                        file_input_tokens += healing_in_tokens
                        file_total_chars_for_cost += len(system_prompt) + len(healing_prompt)
                        
                        func_log_content += f"\n--- TIER 2: HEALING TRIGGERED ---\nInput (Pass 2):\n{healing_prompt}\n"
                        
                        start_time = time.time()
                        healing_response = llm_client.generate_completion(system_prompt, healing_prompt)
                        file_duration += (time.time() - start_time)
                        
                        if healing_response and isinstance(healing_response, dict) and "text" in healing_response:
                            healed_text = healing_response["text"]
                            pass_2_out_tokens = count_llama_tokens(healed_text, tokenizer)
                            func_out_tokens += pass_2_out_tokens
                            file_output_tokens += pass_2_out_tokens
                            file_total_chars_for_cost += len(healed_text)
                            
                            func_log_content += f"Output (Pass 2):\n{healed_text}\n"
                            
                            healed_code = clean_llm_response(healed_text, clean_func_text)
                            healed_bytes = healed_code.encode('utf-8')
                            temp_bytes_healed = bytearray(code_bytes)
                            temp_bytes_healed[start:end] = healed_bytes
                            
                            with open(file_path, 'wb') as f_out: f_out.write(temp_bytes_healed)
                            
                            final_errors_list, final_error_count = run_tsc_check(dest_path)
                            
                            if final_error_count == 0:
                                temp_bytes = temp_bytes_healed
                                cleaned_code = healed_code
                                patch_accepted = True
                                patch_status = "Accepted (Healed)"
                            else:
                                failed_healings += 1
                                patch_accepted = False
                                patch_status = "Rejected (Failed Healing)"
                                build_errors_list = final_errors_list 
                        else:
                            failed_healings += 1
                            patch_accepted = False
                            patch_status = "Rejected (Healing Generation Failed)"
                        
                        if not patch_accepted:
                            # FIX: restaura para code_bytes (estado consolidado até aqui),
                            # não para o original do arquivo — preserva patches anteriores aceitos
                            with open(file_path, 'wb') as f_out: f_out.write(code_bytes)
                            with open(failed_healing_log_path, "a", encoding="utf-8") as f_fail:
                                f_fail.write(f"\n[{rel_path_key} - {func_name}] FALHA IRRECUPERÁVEL DE COMPILAÇÃO:\n")
                                f_fail.write("--- Erros Finais ---\n" + "\n".join(build_errors_list) + "\n")
                                f_fail.write("=========================\n")
                    else:
                        patch_accepted = True
                        patch_status = "Accepted (First Pass)"

                    if patch_accepted:
                        code_bytes = temp_bytes
                        loc_churn += abs(len(cleaned_code.splitlines()) - len(clean_func_text.splitlines()))
                        valid_mods += 1
            
            # === ESCREVE O LOG FINAL DESTA FUNÇÃO ===
            with open(log_file_path, "a", encoding="utf-8") as log_f:
                log_f.write(f"Status: {patch_status}\n")
                log_f.write(f"Total Input Tokens: {func_in_tokens}\n")
                log_f.write(f"Total Output Tokens: {func_out_tokens}\n")
                log_f.write(func_log_content)
                log_f.write("=========================\n")

        # Salva a versão final e consolidada do arquivo
        with open(file_path, 'wb') as f_out: 
            f_out.write(code_bytes)
            
        return valid_mods, failed_healings, loc_churn, file_input_tokens, file_output_tokens, file_total_chars_for_cost, file_duration

    except Exception as e:
        print(f"⚠️  Error in {file_path}: {e}")
        # FIX: tupla de retorno padronizada com 8 valores (era 7, causava ValueError no unpack)
        return 0, 0, 0, 0, 0, 0, 0.0

def pre_compute_total_functions(dest_path):
    print("\n🔍 Calculando o número total de funções a serem processadas...")
    target_dirs_paths = [Path(dest_path) / d for d in TARGET_DIRS]
    total_funcs = 0
    
    for root, dirs, files in os.walk(dest_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        if any(str(Path(root)).startswith(str(t)) for t in target_dirs_paths):
            for f in files:
                if any(f.endswith(ext) for ext in TARGET_EXTENSIONS) and not any(f.endswith(ext) for ext in IGNORE_EXTENSIONS) and f not in IGNORE_FILES:
                    file_path = os.path.join(root, f)
                    try:
                        with open(file_path, 'rb') as file_data:
                            code_bytes = bytearray(file_data.read())
                            functions = extract_functions(code_bytes, language, parser)
                            total_funcs += len(functions)
                    except: pass
    
    print(f"✅ Total de funções mapeadas: {total_funcs}")
    return total_funcs

def run_iteration(treatment, i):
    run_id = f"{treatment}-{i+1}"
    print(f"\n🚀 [ID: {run_id}] LLM Generation Phase ({i+1}/{NUM_ITERATIONS})...")
    
    dest_path = os.path.join(OUTPUT_DIR, run_id)
    if os.path.exists(dest_path): shutil.rmtree(dest_path)
    
    print("   📂 Copiando repositório base (incluindo node_modules)...")
    shutil.copytree(
        BASE_REPO, dest_path,
        symlinks=True,
        ignore=shutil.ignore_patterns('.git', 'dist', '.angular', 'tmp', 'vagrant', 'node_modules')
    )
    os.symlink(
        os.path.abspath(os.path.join(BASE_REPO, "node_modules")),
        os.path.join(dest_path, "node_modules")
    )

    total_funcs = pre_compute_total_functions(dest_path)
    
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

    # FIX: todos os 8 valores desempacotados corretamente; failed_healings agora acumulado
    tot_valid = tot_failed_healings = tot_loc_churn = 0
    tot_in_tokens = tot_out_tokens = tot_chars_for_cost = 0
    tot_time = 0.0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for v, fh, l, in_t, out_t, t_chars, dur in tqdm(
            executor.map(lambda f: process_file(f, treatment, run_id, dest_path), files_to_process),
            total=len(files_to_process),
            desc=f"Refactoring"
        ):
            tot_valid += v
            tot_failed_healings += fh  # FIX: métrica antes perdida
            tot_loc_churn += l
            tot_in_tokens += in_t
            tot_out_tokens += out_t
            tot_chars_for_cost += t_chars
            tot_time += dur
            
    run_cost = calculate_cost_oci(tot_chars_for_cost)
            
    print(f"✅ LLM Phase Complete. Patches: {tot_valid} | Failed Healings: {tot_failed_healings} | Cost: ${run_cost:.4f} | Time: {tot_time:.2f}s")
    print(f"📊 Exact Tokens: {tot_in_tokens} (Input) + {tot_out_tokens} (Output) = {tot_in_tokens + tot_out_tokens} Total")

    # FIX: failed_healings incluído no CSV
    with open(os.path.join(OUTPUT_DIR, "llm_metrics.csv"), "a") as f:
        f.write(f"{run_id},{tot_valid},{tot_failed_healings},{tot_loc_churn},{tot_in_tokens},{tot_out_tokens},{tot_time:.2f},{run_cost:.4f}\n")

def main():
    if not os.path.exists(BASE_REPO): return print(f"❌ Error: {BASE_REPO} not found.")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # FIX: servidor iniciado aqui, dentro de main(), evitando side-effect no import
    start_type_extractor_server()

    # FIX: carregamento dos contextos movido para cá também, após server start e dentro de main()
    if "posecure-extractive" in TREATMENTS:
        if os.path.exists(COMPRESSED_JSON_PATH):
            with open(COMPRESSED_JSON_PATH, "r", encoding="utf-8") as f:
                compressed_contexts.update(json.load(f))
        else:
            sys.exit(f"❌ ERRO FATAL: {COMPRESSED_JSON_PATH} não existe.")

    if "sosecure" in TREATMENTS:
        if os.path.exists(RAW_JSON_PATH):
            with open(RAW_JSON_PATH, "r", encoding="utf-8") as f:
                raw_contexts.update(json.load(f))
        else:
            sys.exit(f"❌ ERRO FATAL: {RAW_JSON_PATH} não existe.")
            
    if "posecure-abstractive" in TREATMENTS:
        if os.path.exists(ABSTRACTIVE_JSON_PATH):
            with open(ABSTRACTIVE_JSON_PATH, "r", encoding="utf-8") as f:
                abstractive_contexts.update(json.load(f))
        else:
            sys.exit(f"❌ ERRO FATAL: {ABSTRACTIVE_JSON_PATH} não existe.")
            
    if "cvefixes" in TREATMENTS:
        if os.path.exists(CVEFIXES_JSON_PATH):
            with open(CVEFIXES_JSON_PATH, "r", encoding="utf-8") as f:
                cvefixes_contexts.update(json.load(f))
        else:
            sys.exit(f"❌ ERRO FATAL: {CVEFIXES_JSON_PATH} não existe.")
    
    csv_path = os.path.join(OUTPUT_DIR, "llm_metrics.csv")
    if not os.path.exists(csv_path):
        with open(csv_path, "w") as f:
            # FIX: cabeçalho do CSV atualizado para incluir Failed_Healings
            f.write("Run_ID,Valid_Patches,Failed_Healings,LOC_Churn,Input_Tokens,Output_Tokens,Total_Time_Sec,Cost_USD\n")

    for treatment in TREATMENTS:
        for i in range(NUM_ITERATIONS): 
            run_iteration(treatment, i)

if __name__ == "__main__":
    main()