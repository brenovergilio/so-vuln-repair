import os
import shutil
import oci
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from tree_sitter_languages import get_language, get_parser
from dotenv import load_dotenv  # <--- IMPORT NOVO

# --- 0. CARREGA VARIÁVEIS DE AMBIENTE ---
# Carrega o arquivo .env que está na mesma pasta
load_dotenv()

# --- 1. CONFIGURAÇÕES DA ORACLE CLOUD ---
OCI_CONFIG_PROFILE = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
OCI_COMPARTMENT_ID = os.getenv("OCI_COMPARTMENT_ID")
OCI_SERVICE_ENDPOINT = os.getenv("OCI_SERVICE_ENDPOINT")
OCI_MODEL_ID = os.getenv("OCI_MODEL_ID")

# Validação de Segurança (Fail fast)
if not OCI_COMPARTMENT_ID:
    raise ValueError("❌ ERRO: OCI_COMPARTMENT_ID não encontrado no arquivo .env")
if not OCI_SERVICE_ENDPOINT:
    raise ValueError("❌ ERRO: OCI_SERVICE_ENDPOINT não encontrado no arquivo .env")

# --- 2. CONFIGURAÇÕES DO EXPERIMENTO ---
BASE_REPO = "./experiment_target"
OUTPUT_DIR = "./experiment_results"
# Converte string do .env para int/float
NUM_ITERATIONS = int(os.getenv("NUM_ITERATIONS", 5))
TEMPERATURE = float(os.getenv("TEMPERATURE", 0.2))

# Extensões e Pastas Alvo
TARGET_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}
TARGET_DIRS = {"routes", "lib", "models", "data"} # Focando no backend/lógica
IGNORE_DIRS = {"node_modules", ".git", "test", "frontend"}

# --- SYSTEM PROMPTS ---
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
3. Use the context to apply specific fixes.
"""

# --- PREPARAÇÃO DO PARSER (Tree-sitter) ---
# Isso garante que pegamos funções inteiras, não pedaços quebrados
language = get_language('javascript') # Funciona para JS e TS na maioria dos casos do tree-sitter-languages
parser = get_parser('javascript')

def setup_experiment_folder(treatment, iteration):
    """Cria a cópia limpa do projeto: juice-shop-llm-raw-1"""
    dest_name = f"juice-shop-{treatment}-{iteration}"
    dest_path = os.path.join(OUTPUT_DIR, dest_name)
    
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
    
    print(f"📂 Clonando para: {dest_path}")
    # Copia tudo, ignorando node_modules e git para ser rápido
    shutil.copytree(BASE_REPO, dest_path, ignore=shutil.ignore_patterns('node_modules', '.git', 'dist'))
    return dest_path

def extract_functions(code_bytes):
    """
    Usa AST para encontrar start/end bytes de todas as funções.
    Retorna uma lista de tuplas (start_byte, end_byte, function_text)
    """
    tree = parser.parse(code_bytes)
    cursor = tree.walk()
    
    funcs = []
    
    # Query para achar declarações de função, métodos e arrow functions
    # Essa query é genérica para JS/TS
    query_scm = """
    (function_declaration) @func
    (function_expression) @func
    (arrow_function) @func
    (method_definition) @func
    """
    query = language.query(query_scm)
    captures = query.captures(tree.root_node)
    
    for node, _ in captures:
        funcs.append((node.start_byte, node.end_byte, code_bytes[node.start_byte:node.end_byte]))
        
    return funcs

def get_rag_context(code_text):
    """
    [Simulação] Aqui entraria sua chamada ao Qdrant.
    Retorna string vazia se não achar nada relevante.
    """
    # Exemplo: Se encontrar "eval(", retorna alerta
    if "eval(" in code_text or "exec(" in code_text:
        return "CRITICAL CONTEXT: This code uses dynamic execution. Replace with safe alternatives."
    return ""

def query_llm(code_text, treatment):
    """Envia para o Ollama e trata o retorno"""
    is_rag = (treatment == "llm-rag")
    
    system_prompt = PROMPT_RAG if is_rag else PROMPT_RAW
    user_content = f"CODE TO FIX:\n{code_text}"
    
    if is_rag:
        context = get_rag_context(code_text)
        if context:
            user_content = f"VULNERABILITY CONTEXT:\n{context}\n\n{user_content}"

    payload = {
        "model": MODEL_NAME,
        "prompt": f"{system_prompt}\n\n{user_content}",
        "stream": False,
        "options": {"temperature": TEMPERATURE, "num_ctx": 4096}
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        if response.status_code == 200:
            return response.json().get("response", "").strip()
    except Exception as e:
        print(f"❌ Erro LLM: {e}")
    
    return None # Falha

def clean_code(llm_output, original_code):
    """Remove markdown (```javascript ... ```) se a LLM alucinar"""
    if "```" in llm_output:
        lines = llm_output.split('\n')
        # Remove primeira e última linha se tiverem ```
        clean_lines = [l for l in lines if not l.strip().startswith("```")]
        return "\n".join(clean_lines)
    
    # Fallback: Se a resposta for muito curta (erro), devolve original
    if len(llm_output) < len(original_code) * 0.5:
        return original_code
        
    return llm_output

def process_file(file_path, treatment):
    """Lê arquivo -> Extrai Funções -> Manda pra LLM -> Remonta Arquivo"""
    try:
        with open(file_path, 'rb') as f:
            code_bytes = f.read()
            
        functions = extract_functions(code_bytes)
        
        # Se não tem funções, pula
        if not functions:
            return 0
            
        # Ordena reverso para substituir do final pro começo (não quebra índices)
        functions.sort(key=lambda x: x[0], reverse=True)
        
        new_code_bytes = bytearray(code_bytes)
        modified_count = 0
        
        for start, end, func_bytes in functions:
            func_text = func_bytes.decode('utf-8', errors='ignore')
            
            # Pula funções muito pequenas (getters/setters simples) ou gigantes
            if len(func_text) < 50 or len(func_text) > 4000:
                continue
                
            # Chama LLM
            llm_response = query_llm(func_text, treatment)
            
            if llm_response:
                cleaned_response = clean_code(llm_response, func_text)
                
                # Substitui no bytearray
                # Atenção: encoding deve bater
                new_bytes = cleaned_response.encode('utf-8')
                new_code_bytes[start:end] = new_bytes
                modified_count += 1
        
        # Salva arquivo modificado
        if modified_count > 0:
            with open(file_path, 'wb') as f:
                f.write(new_code_bytes)
                
        return modified_count

    except Exception as e:
        print(f"⚠️ Erro em {file_path}: {e}")
        return 0

def run_iteration(treatment, i):
    """Roda uma iteração completa de um tratamento"""
    print(f"\n🚀 Iniciando [{treatment.upper()}] - Iteração {i+1}/{NUM_ITERATIONS}")
    
    # 1. Copia Pasta
    target_dir = setup_experiment_folder(treatment, i+1)
    
    # 2. Lista Arquivos Alvo
    files_to_scan = []
    for root, dirs, files in os.walk(target_dir):
        # Filtra diretórios ignorados
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                # Verifica se está numa pasta de interesse
                rel_dir = os.path.relpath(root, target_dir)
                if any(td in rel_dir for td in TARGET_DIRS) or rel_dir == ".":
                    files_to_scan.append(os.path.join(root, file))
    
    print(f"🔍 Arquivos identificados para análise: {len(files_to_scan)}")
    
    # 3. Processa em Paralelo
    # ThreadPool ajuda porque o gargalo é I/O de rede (chamada HTTP ao Ollama)
    total_modifications = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        # Usamos lambda para passar o parametro treatment
        futures = [executor.submit(process_file, f, treatment) for f in files_to_scan]
        
        for future in tqdm(futures, total=len(files_to_scan), desc=f"Processando {treatment}-{i+1}"):
            total_modifications += future.result()
            
    print(f"✅ Iteração concluída. Total de funções reescritas: {total_modifications}")
    return target_dir

def main():
    if not os.path.exists(BASE_REPO):
        print(f"❌ Erro: Pasta base {BASE_REPO} não encontrada.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    treatments = ["llm-raw", "llm-rag"]
    
    for treatment in treatments:
        for i in range(NUM_ITERATIONS):
            final_folder = run_iteration(treatment, i)
            # Aqui você poderia chamar o script do CodeQL automaticamente:
            # subprocess.run(["python3", "analisar_final.py", "--target", final_folder])

if __name__ == "__main__":
    main()