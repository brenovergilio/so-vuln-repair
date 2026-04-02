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
from utils import get_llama_tokenizer, count_llama_tokens, get_dirs_and_extensions, count_syntax_errors, sanitize_code_semantics, extract_functions, extract_graph_context, clean_llm_response, calculate_cost_oci, get_ts_tree_sitter_language_and_parser, get_func_id, get_type_aware_context

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATION ---
BASE_REPO = "./juice-shop"
PROVIDER = os.getenv("PROVIDER", "local")
OUTPUT_DIR = f"./experiment_results/{PROVIDER}/juice-shop"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 3))
TREATMENTS = ["llm-raw", "sosecure", "posecure-extractive", "posecure-abstractive", "cvefixes"]

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
    """Garante que o servidor Node.js é desligado quando o script Python termina (com sucesso ou erro)."""
    global node_server_process
    if node_server_process:
        print("\n🧹 [TEARDOWN] Desligando o Type-Extractor Server (Porta 3001)...")
        node_server_process.terminate()
        try:
            node_server_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            node_server_process.kill()
        # Limpeza agressiva por precaução
        subprocess.run(["fuser", "-k", "-s", "9", "3001/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("   ✅ Servidor Node.js encerrado.")

def start_type_extractor_server():
    """Levanta o servidor Node.js se algum tratamento precisar de RAG de código."""
    global node_server_process
    print("\n⚙️  [SETUP] Verificando necessidade do Type-Extractor Server...")
    
    needs_server = any(t in TREATMENTS for t in ["posecure-abstractive", "posecure-extractive", "cvefixes"])
    if not needs_server:
        print("   ⏩ Tratamentos atuais não exigem contexto estrutural. Servidor Node ignorado.")
        return

    extractor_dir = "./type-extractor"
    if not os.path.exists(extractor_dir):
        print(f"❌ ERRO FATAL: O diretório '{extractor_dir}' não foi encontrado.")
        sys.exit(1)

    print("   🚀 Iniciando o Bi-directional RAG Extractor (Node.js) em background...")
    
    # Mata qualquer processo fantasma que possa ter ficado na porta 3001 de execuções anteriores
    subprocess.run(["fuser", "-k", "-s", "9", "3001/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # IMPORTANTE: Substitua "server.js" pelo nome real do arquivo Node.js que contém o express
    node_server_process = subprocess.Popen(
        ["node", "server.js"], 
        cwd=extractor_dir,
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL
    )

    # Health Check para garantir que o Express iniciou
    print("   ⏳ Aguardando servidor Node.js responder na porta 3001...")
    server_ready = False
    for _ in range(15): # Tenta durante 15 segundos
        try:
            # Fazemos um GET. O Express vai retornar 404 (pois só temos rota POST), 
            # mas retornar 404 significa que o servidor está online e vivo!
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

# Registra a função de limpeza para rodar na saída do script
atexit.register(cleanup_node_server)

# Inicia a orquestração do servidor antes de carregar os JSONs
start_type_extractor_server()

# Variáveis separadas para carregar os conteúdos
compressed_contexts = {}
raw_contexts = {}
abstractive_contexts = {}
cvefixes_contexts = {}

# 1. Verifica e carrega para o tratamento COM compressão
if "posecure-extractive" in TREATMENTS:
    if os.path.exists(COMPRESSED_JSON_PATH):
        print(f"📦 Carregando RAG comprimido de: {COMPRESSED_JSON_PATH}")
        with open(COMPRESSED_JSON_PATH, "r", encoding="utf-8") as f:
            compressed_contexts = json.load(f)
    else:
        print(f"❌ ERRO FATAL: O tratamento 'posecure-extractive' foi selecionado, mas o arquivo {COMPRESSED_JSON_PATH} não existe. Abortando.")
        sys.exit(1)

# 2. Verifica e carrega para o tratamento SEM compressão (SOSecure original)
if "sosecure" in TREATMENTS:
    if os.path.exists(RAW_JSON_PATH):
        print(f"📦 Carregando RAG SOSecure bruto de: {RAW_JSON_PATH}")
        with open(RAW_JSON_PATH, "r", encoding="utf-8") as f:
            raw_contexts = json.load(f)
    else:
        print(f"❌ ERRO FATAL: O tratamento 'sosecure' foi selecionado, mas o arquivo {RAW_JSON_PATH} não existe. Abortando.")
        sys.exit(1)
        
if "posecure-abstractive" in TREATMENTS:
    if os.path.exists(ABSTRACTIVE_JSON_PATH):
        print(f"📦 Carregando RAG POSECURE de: {ABSTRACTIVE_JSON_PATH}")
        with open(ABSTRACTIVE_JSON_PATH, "r", encoding="utf-8") as f:
            abstractive_contexts = json.load(f)
    else:
        print(f"❌ ERRO FATAL: O tratamento 'posecure' foi selecionado, mas o arquivo {ABSTRACTIVE_JSON_PATH} não existe. Abortando.")
        sys.exit(1)
        
if "cvefixes" in TREATMENTS:
    if os.path.exists(ABSTRACTIVE_JSON_PATH):
        print(f"📦 Carregando RAG CVEFixes de: {CVEFIXES_JSON_PATH}")
        with open(CVEFIXES_JSON_PATH, "r", encoding="utf-8") as f:
            cvefixes_contexts = json.load(f)
    else:
        print(f"❌ ERRO FATAL: O tratamento 'cvefixes' foi selecionado, mas o arquivo {CVEFIXES_JSON_PATH} não existe. Abortando.")
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

def get_prompt_posecure(query, context, type_signatures=""):
    # Bloco estrutural (AST / LSP)
    type_block = ""
    if type_signatures and type_signatures.strip():
        type_block = f"""
Below are the EXACT type signatures and contracts for the libraries and local modules imported in this file. 
STRICTLY ADHERE to these definitions to prevent compilation errors. Do not hallucinate parameters or methods that do not exist in these signatures:
---
{type_signatures}
---
"""

    # Bloco semântico (StackOverflow / Qdrant)
    context_block = ""
    if context and context.strip():
        context_block = f"""Below is a related StackOverflow additional context that may be helpful:
---
{context}
---
"""

    # Prompt Final POSecure
    return f"""Given the following code:

{query}

Does this code have any security vulnerabilities? 
{context_block}
{type_block}
**Instructions:**
- Review the code for any security flaws.
- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.
- If no security issues are found, output "No security issues found".
- Ensure that the fixes do not alter the original intent of the code.
- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
- MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.
- RETURN ONLY THE CODE. No markdown, no explanation.
- It is imperative that the new code should not have any CWE or CVE security errors.

**STRICT COMPILATION & FRAMEWORK RULES (CRITICAL):**
1. NO NEW IMPORTS: You are modifying an isolated function block. DO NOT invoke external libraries (like DOMPurify, Joi, xss, etc.) or RxJS operators (`of`, `throwError`) unless they are ALREADY defined in the [LIBRARY SIGNATURES]. 
2. CLASS METHOD PRESERVATION: If the provided code is a class method (e.g., `methodName(...) {{ ... }}`), return it EXACTLY as a class method. DO NOT prepend the `function` keyword or convert it to an arrow function property.
3. TYPESCRIPT STRICT ERRORS: In `catch (error)` blocks, assume `error` is of type `unknown`. You MUST typecast it (e.g., `if (error instanceof Error) {{ ... }}`) before accessing properties like `.message`.
4. NO MODERN ES2022 ERROR CAUSES: DO NOT use the {{ cause: error }} object when instantiating Errors (e.g., do not write `new Error(msg, {{ cause: err }})`). Strictly use the standard `new Error(msg)`.
5. STRICT TYPE PRESERVATION: Do not change the original nullability of variables or return types. Do not reassign variables declared with `const`.
6. ANGULAR SANITIZER AWARENESS: If you use Angular's `this.sanitizer.sanitize()`, it strictly requires TWO arguments (SecurityContext and the value). If context is unavailable, use standard JS regex/type-checking to prevent XSS.
7. ENVIRONMENT ISOLATION: Do not mix browser modules with Node.js modules. If the code uses Angular injections (like `this.router`), DO NOT use Node.js native modules like `crypto.createHash()`.
8. MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.
"""

def get_prompt_cvefixes(query, context, type_signatures=""):
    # Bloco estrutural (AST / LSP)
    type_block = ""
    if type_signatures and type_signatures.strip():
        type_block = f"""
Below are the EXACT type signatures and contracts for the libraries and local modules imported in this file. 
STRICTLY ADHERE to these definitions to prevent compilation errors. Do not hallucinate parameters or methods that do not exist in these signatures:
---
{type_signatures}
---
"""

    # Bloco semântico (CVEfixes / Qdrant)
    context_block = ""
    if context and context.strip():
        context_block = f"""Below are related real-world vulnerability patterns (CVEs) and their secure fixes that may be helpful as a reference for your correction:
---
{context}
---
"""

    # Prompt Final CVEfixes
    return f"""Given the following code:

{query}

Does this code have any security vulnerabilities? 
{context_block}
{type_block}
**Instructions:**
- Review the code for any security flaws.
- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.
- If no security issues are found, output "No security issues found".
- Ensure that the fixes do not alter the original intent of the code.
- KEEP THE EXACT SAME FUNCTION SIGNATURE (input arguments, return type and name).
- MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.
- RETURN ONLY THE CODE. No markdown, no explanation.
- It is imperative that the new code should not have any CWE or CVE security errors.

**STRICT COMPILATION & FRAMEWORK RULES (CRITICAL):**
1. NO NEW IMPORTS: You are modifying an isolated function block. DO NOT invoke external libraries (like DOMPurify, Joi, xss, etc.) or RxJS operators (`of`, `throwError`) unless they are ALREADY defined in the [LIBRARY SIGNATURES]. 
2. CLASS METHOD PRESERVATION: If the provided code is a class method (e.g., `methodName(...) {{ ... }}`), return it EXACTLY as a class method. DO NOT prepend the `function` keyword or convert it to an arrow function property.
3. TYPESCRIPT STRICT ERRORS: In `catch (error)` blocks, assume `error` is of type `unknown`. You MUST typecast it (e.g., `if (error instanceof Error) {{ ... }}`) before accessing properties like `.message`.
4. NO MODERN ES2022 ERROR CAUSES: DO NOT use the {{ cause: error }} object when instantiating Errors (e.g., do not write `new Error(msg, {{ cause: err }})`). Strictly use the standard `new Error(msg)`.
5. STRICT TYPE PRESERVATION: Do not change the original nullability of variables or return types. Do not reassign variables declared with `const`.
6. ANGULAR SANITIZER AWARENESS: If you use Angular's `this.sanitizer.sanitize()`, it strictly requires TWO arguments (SecurityContext and the value). If context is unavailable, use standard JS regex/type-checking to prevent XSS.
7. ENVIRONMENT ISOLATION: Do not mix browser modules with Node.js modules. If the code uses Angular injections (like `this.router`), DO NOT use Node.js native modules like `crypto.createHash()`.
8. MUST MATCH THE TYPE CONTEXT: When calling external libraries or local modules, strictly use the arguments and types defined in the provided Type Context.
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
        
        with open(file_path, 'rb') as f: code_bytes = bytearray(f.read())
        tree = parser.parse(bytes(code_bytes))
        initial_errors = count_syntax_errors(tree, language, parser)
            
        functions = extract_functions(code_bytes, language, parser)
        if not functions: return 0, 0, 0, 0, 0, 0, 0.0
            
        # 🚀 O SEGREDO: Processamento Bottom-Up!
        # Ordenamos pelas funções que estão no FINAL do arquivo (reverse=True)
        # Assim, modificar os bytes lá embaixo não corrompe a posição das funções de cima.
        functions.sort(key=lambda x: x[0], reverse=True)
        
        rel_path_key = os.path.relpath(file_path, dest_path)
        
        for func_tuple in functions:
            start = func_tuple[0]
            end = func_tuple[1]
            func_name = func_tuple[3] if len(func_tuple) > 3 else "Unknown_Function"
            
            original_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
            clean_func_text = sanitize_code_semantics(original_func_text, language, parser)
            func_id = get_func_id(clean_func_text)
            
            # --- MONTAGEM DO PROMPT (Mantida igual ao seu original) ---
            system_prompt = PROMPT_SYS
            user_content = ""
            
            if treatment == "llm-raw":
                user_content = get_prompt_raw(clean_func_text)
            else:                
                if treatment == "posecure-extractive":
                    # Pega o resumo extrativo (TF-IDF/BM25) em vez do gerado por LLM
                    extractive_summary = compressed_contexts.get(rel_path_key, {}).get(func_id, "")
                    final_rag_context = ""
                    if extractive_summary: 
                        final_rag_context = f"[COMMUNITY SECURITY DISCUSSIONS]\n{extractive_summary}"
                    
                    # Usa o caminho absoluto para o Oráculo Node.js funcionar (Tipagem Estrita)
                    rel_path_to_original = os.path.join(BASE_REPO, rel_path_key)
                    original_repo_file_path = os.path.abspath(rel_path_to_original)
                    type_signatures = get_type_aware_context(original_repo_file_path, clean_func_text)
                    
                    # Usa o construtor de prompt forte do POSecure
                    user_content = get_prompt_posecure(clean_func_text, final_rag_context, type_signatures)
                        
                elif treatment == "sosecure":
                    # O baseline original do SOSecure (texto cru e sem tipagem)
                    final_rag_context = raw_contexts.get(rel_path_key, {}).get(func_id, "")
                    user_content = get_prompt_rag(clean_func_text, final_rag_context)
                    
                elif treatment == "posecure-abstractive": # (Este é o posecure-abstractive)
                    # Pega o resumo abstrativo gerado pelo LLM de 3B
                    abstractive_summary = abstractive_contexts.get(rel_path_key, {}).get(func_id, "")
                    final_rag_context = ""
                    if abstractive_summary: 
                        final_rag_context = f"[COMMUNITY SECURITY DISCUSSIONS]\n{abstractive_summary}"
                    
                    # Usa o caminho absoluto para o Oráculo Node.js funcionar (Tipagem Estrita)
                    rel_path_to_original = os.path.join(BASE_REPO, rel_path_key)
                    original_repo_file_path = os.path.abspath(rel_path_to_original)
                    type_signatures = get_type_aware_context(original_repo_file_path, clean_func_text)
                    
                    # Usa o construtor de prompt forte do POSecure
                    user_content = get_prompt_posecure(clean_func_text, final_rag_context, type_signatures)
                    
                elif treatment == "cvefixes": # (Este é o cvefixes)
                    cvefixes_examples = cvefixes_contexts.get(rel_path_key, {}).get(func_id, "")
                    final_rag_context = ""
                    if cvefixes_examples: 
                        final_rag_context = f"[KNOWN VULNERABILITY FIXES]\n{cvefixes_examples}"
                    
                    rel_path_to_original = os.path.join(BASE_REPO, rel_path_key)
                    original_repo_file_path = os.path.abspath(rel_path_to_original)
                    type_signatures = get_type_aware_context(original_repo_file_path, clean_func_text)
                    
                    user_content = get_prompt_cvefixes(clean_func_text, final_rag_context, type_signatures)

            if not user_content: continue

            full_prompt = system_prompt + "\n" + user_content
            input_tokens_count = count_llama_tokens(full_prompt, tokenizer)
            file_input_tokens += input_tokens_count
            
            start_time = time.time()
            llm_response = llm_client.generate_completion(system_prompt, user_content)
            file_duration += (time.time() - start_time)
            
            if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                response_text = llm_response["text"]
                final_output_tokens_count = count_llama_tokens(response_text, tokenizer)
                file_output_tokens += final_output_tokens_count
                file_total_chars_for_cost += len(full_prompt) + len(response_text)
                
                cleaned_code = clean_llm_response(response_text, clean_func_text)
                
                # Se o 70B propôs uma modificação válida
                if cleaned_code != clean_func_text.strip():
                    new_bytes = cleaned_code.encode('utf-8')
                    temp_bytes = bytearray(code_bytes)
                    temp_bytes[start:end] = new_bytes
                    
                    # Verifica se o patch quebrou a sintaxe do arquivo
                    if count_syntax_errors(parser.parse(bytes(temp_bytes)), language, parser) > initial_errors:
                        syntax_errors += 1
                        continue # Rejeita o patch e mantém o código vulnerável original
                    
                    # APLICA O PATCH NA MEMÓRIA!
                    code_bytes = temp_bytes
                    loc_churn += abs(len(cleaned_code.splitlines()) - len(clean_func_text.splitlines()))
                    valid_mods += 1
            
            # --- LOG DA FUNÇÃO ---
            log_base_dir = os.path.join(OUTPUT_DIR, f"{run_id}_logs")
            os.makedirs(os.path.dirname(os.path.join(log_base_dir, rel_path_key)), exist_ok=True)
            log_file_path = os.path.join(log_base_dir, rel_path_key + ".txt")
            
            with open(log_file_path, "a", encoding="utf-8") as log_f:
                log_f.write(f"Function: {func_name}\n")
                log_f.write(f"Input Tokens: {input_tokens_count}\n")
                log_f.write(f"Output Tokens: {file_output_tokens}\n")
                log_f.write(f"Input:\n{user_content}\n")
                log_f.write(f"Output:\n{llm_response.get('text', '') if isinstance(llm_response, dict) else ''}\n")
                log_f.write("=========================\n")

        # Salva o arquivo no disco apenas UMA VEZ no final, com todos os patches aplicados!
        with open(file_path, 'wb') as f_out: 
            f_out.write(code_bytes)
            
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