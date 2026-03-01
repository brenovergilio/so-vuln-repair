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
# Important directories in Juice Shop
TARGET_DIRS = {"routes", "models", "frontend/src/app"} 
# Directories to ignore
IGNORE_DIRS = {"node_modules", ".git", "test", "dist", ".angular", "e2e", "vagrant"}

# --- OCI PRICING CONFIGURATION ---
# A OCI cobra a categoria "Large Meta" (Llama 3.1 70B Instruct) a $0.0018 por 10.000 caracteres.
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
    print(f"❌ FATAL: Could not initialize OCI Client. Check .env file. Error: {e}")
    exit(1)
    
def count_syntax_errors(tree):
    query = Query(language, "(ERROR) @err")
    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)
    
    # Se não achar nenhum erro, retorna 0 (tamanho de uma lista vazia)
    return len(captures.get("err", []))

def sanitize_code_semantics(text: str) -> str:
    text_bytes = bytearray(text.encode('utf-8'))
    tree = parser.parse(bytes(text_bytes))
    
    # Captura comentários E chamadas de função
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
    
    # 1. Coleta comentários
    if "comment" in captures:
        nodes_to_remove.extend(captures["comment"])
        
    # 2. Coleta chamadas de função com "challenge" no nome
    if "call" in captures and "func_name" in captures:
        # Relaciona o nome da função com a chamada completa
        for call_node, name_node in zip(captures["call"], captures["func_name"]):
            name = bytes(text_bytes[name_node.start_byte:name_node.end_byte]).decode('utf-8').lower()
            if "challenge" in name:
                nodes_to_remove.append(call_node)

    # 3. Remove duplicatas e ordena do fim para o início do arquivo
    nodes_to_remove = sorted(list(set(nodes_to_remove)), key=lambda n: n.start_byte, reverse=True)
    
    for node in nodes_to_remove:
        # Remove também eventuais vírgulas ou pontos-e-vírgula residuais se necessário, 
        # mas fatiar os bytes do nó já limpa a chamada.
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
        # 1. Tenta pegar o nome da função (se for declaração ou método)
        name_node = node.child_by_field_name("name")
        func_name = ""
        
        if name_node:
            func_name = code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        else:
            # 2. Se for uma função anônima atribuída a uma variável (ex: const meuChallenge = () => {})
            parent = node.parent
            if parent and parent.type == "variable_declarator":
                name_node = parent.child_by_field_name("name")
                if name_node:
                    func_name = code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        
        # --- O FILTRO DE RUÍDO ---
        if "challenge" in func_name.lower():
            continue
            
        funcs.append((node.start_byte, node.end_byte, node.end_byte - node.start_byte))
        
    return funcs

def clean_llm_response(response, original_code):
    if not response: return original_code
    match = re.search(r'```(?:javascript|typescript|js|ts)?\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else response.strip()

def calculate_cost_oci(total_chars):
    return (total_chars / 10000.0) * OCI_PRICE_PER_10K_CHARS

def process_file(file_path, treatment):
    try:
        valid_mods = 0
        syntax_errors = 0
        loc_churn = 0
        file_input_tokens = 0
        file_output_tokens = 0
        file_total_chars_for_cost = 0 # Mantido apenas para calcular o custo na OCI
        file_duration = 0.0
        processed_functions = set()
        
        max_passes = 5 
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
            
            for start, end, _ in functions:
                original_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
                
                # Limpa os comentários para não dar gabarito ao Llama
                clean_func_text = sanitize_code_semantics(original_func_text)
                
                func_hash = hash(clean_func_text)
                if func_hash in processed_functions: continue
                processed_functions.add(func_hash)
                
                system_prompt = PROMPT_RAG if treatment == "llm-rag" else PROMPT_RAW
                
                # Enviamos a versão LIMPA para a IA
                user_content = f"CODE TO FIX:\n{clean_func_text}"
                
                if treatment == "llm-rag" and qdrant_client and sparse_model:
                    try:
                        # 1. Gera o vetor esparso do código vulnerável (BM25)
                        sparse_generator = sparse_model.embed([clean_func_text])
                        sparse_vector_obj = list(sparse_generator)[0]
                        sparse_vector = models.SparseVector(
                            indices=sparse_vector_obj.indices.tolist(),
                            values=sparse_vector_obj.values.tolist()
                        )
                        
                        # 2. Busca os Top-5 vizinhos no Qdrant
                        results = qdrant_client.query_points(
                            collection_name=COLLECTION_NAME,
                            query=sparse_vector,
                            using="bm25",
                            limit=5, 
                        )
                        
                        # 3. Monta o contexto juntando a resposta COMPLETA e TODOS os comentários (SOSecure)
                        context_blocks = []
                        for hit in results.points:
                            p = hit.payload or {}
                            answer_body = p.get('body', '')
                            comments = p.get('comments', [])
                            
                            # Monta o bloco com a resposta e sua thread inteira de comentários
                            block = f"--- Post Answer ---\n{answer_body}\n\nComments:\n"
                            block += "\n".join([f"- {c}" for c in comments])
                            
                            context_blocks.append(block)
                                
                        # Separa as 5 respostas recuperadas
                        context = "\n\n=======================\n\n".join(context_blocks)
                        # Injeta o contexto no prompt do usuário
                        if context:
                            user_content = f"COMMUNITY SECURITY DISCUSSION:\n{context}\n\n{user_content}"
                            
                    except Exception as e:
                        print(f"   ⚠️ RAG Retrieval failed: {e}")

                # Conta os tokens reais do input antes de enviar
                full_prompt = system_prompt + "\n" + user_content
                file_input_tokens += count_llama_tokens(full_prompt)

                start_time = time.time()
                llm_response = llm_client.generate_completion(system_prompt, user_content)
                file_duration += (time.time() - start_time)
                
                if llm_response and isinstance(llm_response, dict) and "text" in llm_response:
                    response_text = llm_response["text"]
                    
                    #print(f"\n🤖 [RESPOSTA DA IA - {os.path.basename(file_path)}]")
                    #print(response_text)
                    #print("=" * 60 + "\n")
                    
                    # Conta os tokens reais do output recebido
                    file_output_tokens += count_llama_tokens(response_text)
                    
                    # Acumula caracteres para o cálculo de custo da Oracle
                    file_total_chars_for_cost += len(full_prompt) + len(response_text)
                    
                    cleaned_code = clean_llm_response(response_text, clean_func_text)
                    
                    # Comparamos com o clean_func_text. Se for diferente, houve refatoração real!
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
            files_to_process.extend([os.path.join(root, f) for f in files if any(f.endswith(ext) for ext in TARGET_EXTENSIONS)])

    tot_valid = tot_syntax_err = tot_loc_churn = tot_in_tokens = tot_out_tokens = tot_chars_for_cost = 0
    tot_time = 0.0
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        for v, s, l, in_t, out_t, t_chars, dur in tqdm(executor.map(lambda f: process_file(f, treatment), files_to_process), total=len(files_to_process), desc=f"Refactoring"):
            tot_valid += v; tot_syntax_err += s; tot_loc_churn += l
            tot_in_tokens += in_t; tot_out_tokens += out_t; tot_chars_for_cost += t_chars
            tot_time += dur
            
    run_cost = calculate_cost_oci(tot_chars_for_cost)
            
    print(f"✅ LLM Phase Complete. Patches: {tot_valid} | Cost: ${run_cost:.4f} | Time: {tot_time:.2f}s")
    print(f"📊 Exact Tokens: {tot_in_tokens} (Input) + {tot_out_tokens} (Output) = {tot_in_tokens + tot_out_tokens} Total")

    with open(os.path.join(OUTPUT_DIR, "llm_metrics.csv"), "a") as f:
        # Escreve os tokens reais no CSV
        f.write(f"{run_id},{tot_valid},{tot_syntax_err},{tot_loc_churn},{tot_in_tokens},{tot_out_tokens},{tot_time:.2f},{run_cost:.4f}\n")

def main():
    if not os.path.exists(BASE_REPO): return print(f"❌ Error: {BASE_REPO} not found.")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    csv_path = os.path.join(OUTPUT_DIR, "llm_metrics.csv")
    if not os.path.exists(csv_path):
        # Atualiza o cabeçalho para refletir as novas colunas
        with open(csv_path, "w") as f: f.write("Run_ID,Valid_Patches,Syntax_Errors_Rejected,LOC_Churn,Input_Tokens,Output_Tokens,Total_Time_Sec,Cost_USD\n")

    for treatment in ["llm-rag"]: # ["llm-raw", "llm-rag"]
        for i in range(NUM_ITERATIONS): run_iteration(treatment, i)

if __name__ == "__main__":
    main()