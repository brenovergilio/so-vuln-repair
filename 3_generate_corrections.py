import os
import time
import shutil
import re
import tree_sitter_typescript as tsts
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from tree_sitter import Language, Parser, Query, QueryCursor
from dotenv import load_dotenv
from qdrant_client import QdrantClient, models
from fastembed import SparseTextEmbedding

# --- CUSTOM MODULES ---
from llm_client import LLMClient

# --- HUGGING FACE TOKENIZER ---
from transformers import AutoTokenizer

# --- LOAD ENV ---
load_dotenv()

# --- CONFIGURATION ---
BASE_REPO = "./juice-shop"
PROVIDER = os.getenv("PROVIDER", "local")
OUTPUT_DIR = f"./experiment_results/{PROVIDER}/juice-shop"
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 3))

# Files to analyze
TARGET_EXTENSIONS = {".ts"}
# Extensions to explicitly ignore
IGNORE_EXTENSIONS = {".spec.ts"}
# Important directories in Juice Shop
TARGET_DIRS = {"routes", "models", "frontend/src/app"} 
# Directories to ignore
IGNORE_DIRS = {"node_modules", ".git", "test", "dist", ".angular", "e2e", "vagrant", "assets", "environments"}
# Arquivos que serão bloqueados para não quebrar a arquitetura de challenges
IGNORE_FILES = {"verify.ts", "vulnCodeFixes.ts", "vulnCodeSnippet.ts"}

# --- OCI PRICING CONFIGURATION ---
OCI_PRICE_PER_10K_CHARS = 0.0018

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

# --- TOKENIZER SETUP ---
print("⏳ Loading Llama 3.1 Tokenizer...")
try:
    tokenizer = AutoTokenizer.from_pretrained("unsloth/Meta-Llama-3.1-8B-Instruct")
    print("✅ Tokenizer loaded.")
except Exception as e:
    print(f"❌ Error loading tokenizer: {e}")
    tokenizer = None
    
# --- QDRANT (RAG) SETUP ---
print("⏳ Loading Qdrant (BM25)...")
COLLECTION_NAME = "sosecure_bm25_js_ts"
try:
    qdrant_client = QdrantClient(host="localhost", port=6333)
    sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")
    print("✅ Qdrant loaded.")
except Exception as e:
    print(f"❌ Error loading Qdrant: {e}")
    qdrant_client, sparse_model = None, None

def count_llama_tokens(text: str) -> int:
    """Counts exact tokens using Llama 3.1 vocabulary"""
    if not text or tokenizer is None:
        return 0
    return len(tokenizer.encode(text))

# --- TREE-SITTER SETUP ---
language = Language(tsts.language_typescript())
parser = Parser(language)

try:
    llm_client = LLMClient(provider=PROVIDER)
except Exception as e:
    print(f"❌ FATAL: Could not initialize LLM Client. Check .env file. Error: {e}")
    exit(1)
    
def count_syntax_errors(tree):
    query = Query(language, "(ERROR) @err")
    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)
    return len(captures.get("err", []))

def sanitize_code_semantics(text: str) -> str:
    text_bytes = bytearray(text.encode('utf-8'))
    tree = parser.parse(bytes(text_bytes))
    
    query_scm = """
    (comment) @comment
    (call_expression 
        function: (identifier) @func_name
    ) @call
    """
    query = Query(language, query_scm)
    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)
    
    nodes_to_remove = []
    
    if "comment" in captures:
        for comment_node in captures["comment"]:
            comment_text = text_bytes[comment_node.start_byte:comment_node.end_byte].decode('utf-8').lower()
            if not any(k in comment_text for k in ["eslint", "typescript", "@ts"]):
                nodes_to_remove.append(comment_node)
        
    if "call" in captures and "func_name" in captures:
        for call_node, name_node in zip(captures["call"], captures["func_name"]):
            name = bytes(text_bytes[name_node.start_byte:name_node.end_byte]).decode('utf-8').lower()
            if "challenge" in name.lower():
                nodes_to_remove.append(call_node)

    nodes_to_remove = sorted(list(set(nodes_to_remove)), key=lambda n: n.start_byte, reverse=True)
    
    for node in nodes_to_remove:
        del text_bytes[node.start_byte:node.end_byte]
        
    return text_bytes.decode('utf-8').strip()

def extract_functions(code_bytes):
    tree = parser.parse(code_bytes)
    query_scm = """
    (function_declaration) @func
    (function_expression) @func
    (arrow_function) @func
    (method_definition) @func
    """
    query = Query(language, query_scm)
    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)
    
    funcs = []
    for node in captures.get("func", []):
        name_node = node.child_by_field_name("name")
        func_name = ""
        
        if name_node:
            func_name = code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        else:
            parent = node.parent
            if parent and parent.type == "variable_declarator":
                name_node = parent.child_by_field_name("name")
                if name_node:
                    func_name = code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        
        if "challenge" in func_name.lower():
            continue
            
        funcs.append((node.start_byte, node.end_byte, node.end_byte - node.start_byte, func_name))
        
    return funcs

def extract_graph_context(code_bytes):
    """
    Extracts all ES6 imports and CommonJS requires from the file to provide
    1-hop architectural context to the LLM, reducing API hallucinations.
    """
    tree = parser.parse(code_bytes)
    
    query_scm = """
    (import_statement) @import
    (import_require_clause) @import_req
    (lexical_declaration) @decl
    (variable_declaration) @decl
    """
    query = Query(language, query_scm)
    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)
    
    dependencies = []
    
    if "import" in captures:
        for node in captures["import"]:
            dependencies.append(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
            
    if "import_req" in captures:
        for node in captures["import_req"]:
            parent = node.parent
            if parent:
                dependencies.append(code_bytes[parent.start_byte:parent.end_byte].decode('utf-8'))
    
    if "decl" in captures:
        for node in captures["decl"]:
            text = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
            if "require(" in text.replace(" ", ""):
                dependencies.append(text)
                
    unique_deps = []
    for d in dependencies:
        if d not in unique_deps:
            unique_deps.append(d)
            
    return "\n".join(unique_deps)

def clean_llm_response(response, original_code):
    if not response: return original_code
    
    # Extrai estritamente o código que a IA jogou no Markdown
    match = re.search(r'```(?:javascript|typescript|js|ts)?\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
    cleaned = match.group(1).strip() if match else response.strip()
    
    # Previne a alucinação extra da IA onde ela as vezes retorna os prompts junto com a resposta
    cleaned = re.sub(r'^(CODE TO FIX:|COMMUNITY SECURITY DISCUSSION:)\s*', '', cleaned, flags=re.IGNORECASE).strip()
    
    return cleaned

def calculate_cost_oci(total_chars):
    return (total_chars / 10000.0) * OCI_PRICE_PER_10K_CHARS

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
            initial_errors = count_syntax_errors(tree)
                
            functions = extract_functions(code_bytes)
            if not functions: break
                
            functions.sort(key=lambda x: x[2])
            modification_made_in_this_pass = False
            
            for func_tuple in functions:
                start = func_tuple[0]
                end = func_tuple[1]
                func_name = func_tuple[3] if len(func_tuple) > 3 else "Unknown_Function"
                
                original_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
                clean_func_text = sanitize_code_semantics(original_func_text)
                
                func_hash = hash(clean_func_text)
                if func_hash in processed_functions: continue
                processed_functions.add(func_hash)
                
                # --- MONTAGEM BASE DO PROMPT ---
                system_prompt = PROMPT_RAW if treatment == "llm-raw" else PROMPT_RAG
                user_content = f"CODE TO FIX:\n{clean_func_text}"
                
                # --- ADIÇÃO DO GRAFO APENAS NO TRATAMENTO COMPLETO ---
                if treatment == "llm-graph-compressed-rag":
                    graph_context_text = extract_graph_context(code_bytes)
                    if graph_context_text:
                        user_content = f"GRAPH CONTEXT (Dependencies & Imports):\n{graph_context_text}\n\n{user_content}"
                
                # --- RECUPERAÇÃO E COMPRESSÃO RAG ---
                if treatment in ["llm-rag", "llm-graph-compressed-rag"] and qdrant_client and sparse_model:
                    try:
                        sparse_generator = sparse_model.embed([clean_func_text])
                        sparse_vector_obj = list(sparse_generator)[0]
                        sparse_vector = models.SparseVector(
                            indices=sparse_vector_obj.indices.tolist(),
                            values=sparse_vector_obj.values.tolist()
                        )
                        
                        results = qdrant_client.query_points(
                            collection_name=COLLECTION_NAME,
                            query=sparse_vector,
                            using="bm25",
                            limit=5, 
                        )
                        
                        context_blocks = []
                        for hit in results.points:
                            p = hit.payload or {}
                            answer_body = p.get('body', '')
                            comments = p.get('comments', [])
                            
                            block = f"--- Post Answer ---\n{answer_body}\n\nComments:\n"
                            block += "\n".join([f"- {c}" for c in comments])
                            context_blocks.append(block)
                                
                        if context_blocks:
                            raw_context = "\n\n=======================\n\n".join(context_blocks)
                            
                            # Tratamento llm-rag: Usa o contexto bruto
                            if treatment == "llm-rag":
                                user_content = f"COMMUNITY SECURITY DISCUSSION:\n{raw_context}\n\n{user_content}"
                            
                            # Tratamento llm-graph-compressed-rag: Comprime o contexto via LLM
                            elif treatment == "llm-graph-compressed-rag":
                                compressor_sys_prompt = (
                                    "You are a Cyber Security Knowledge Extractor. "
                                    "Read the following community discussions and extract a concise, highly technical summary "
                                    "on how to fix the specific vulnerability in the provided code. "
                                    "Ignore pleasantries and irrelevant text. Keep the summary under 150 words."
                                )
                                compressor_user_prompt = f"CODE TO FIX:\n{clean_func_text}\n\nCOMMUNITY DISCUSSIONS:\n{raw_context}"
                                
                                try:
                                    file_input_tokens += count_llama_tokens(compressor_sys_prompt + "\n" + compressor_user_prompt)
                                    
                                    start_time_comp = time.time()
                                    comp_response = llm_client.generate_completion(compressor_sys_prompt, compressor_user_prompt)
                                    file_duration += (time.time() - start_time_comp)
                                    
                                    if comp_response and isinstance(comp_response, dict) and "text" in comp_response:
                                        compressed_context = comp_response["text"].strip()
                                        file_output_tokens += count_llama_tokens(compressed_context)
                                        file_total_chars_for_cost += len(compressor_sys_prompt + compressor_user_prompt) + len(compressed_context)
                                        
                                        user_content = f"COMMUNITY SECURITY MITIGATION (Compressed):\n{compressed_context}\n\n{user_content}"
                                    else:
                                        user_content = f"COMMUNITY SECURITY DISCUSSION:\n{raw_context}\n\n{user_content}"
                                except Exception as e:
                                    print(f"   ⚠️ Abstractive Compression via API failed: {e}")
                                    user_content = f"COMMUNITY SECURITY DISCUSSION:\n{raw_context}\n\n{user_content}"
                            
                    except Exception as e:
                        print(f"   ⚠️ RAG Retrieval failed: {e}")

                full_prompt = system_prompt + "\n" + user_content
                final_response_text = ""
                
                # --- LOOP DE TENTATIVAS PARA O PATCH FINAL ---
                for attempt in range(5):
                    file_input_tokens += count_llama_tokens(full_prompt)

                    start_time = time.time()
                    llm_response = llm_client.generate_completion(system_prompt, user_content)
                    file_duration += (time.time() - start_time)
                    
                    if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                        response_text = llm_response["text"]
                        final_response_text = response_text
                        
                        file_output_tokens += count_llama_tokens(response_text)
                        file_total_chars_for_cost += len(full_prompt) + len(response_text)
                        
                        cleaned_code = clean_llm_response(response_text, clean_func_text)
                        
                        if cleaned_code != clean_func_text.strip():
                            new_bytes = cleaned_code.encode('utf-8')
                            temp_bytes = bytearray(code_bytes)
                            temp_bytes[start:end] = new_bytes
                            
                            if count_syntax_errors(parser.parse(bytes(temp_bytes))) > initial_errors:
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
                
                # --- REGISTRO DO LOG DO ARQUIVO ---
                log_base_dir = os.path.join(OUTPUT_DIR, f"{run_id}_logs")
                rel_path = os.path.relpath(file_path, dest_path)
                log_file_path = os.path.join(log_base_dir, rel_path + ".txt")
                
                os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
                
                with open(log_file_path, "a", encoding="utf-8") as log_f:
                    log_f.write(f"File Path: {file_path}\n")
                    log_f.write(f"Function: {func_name}\n")
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
    
    with ThreadPoolExecutor(max_workers=2) as executor:
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

    # --- NOVO: Loop principal rodando e comparando os 3 tratamentos ---
    for treatment in ["llm-raw", "llm-rag", "llm-graph-compressed-rag"]: 
        for i in range(NUM_ITERATIONS): 
            run_iteration(treatment, i)

if __name__ == "__main__":
    main()