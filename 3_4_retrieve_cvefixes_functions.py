from utils import get_dirs_and_extensions, get_func_id, get_qdrant_client, get_ts_tree_sitter_language_and_parser, sanitize_code_semantics, extract_functions, retrieve_from_qdrant
import os
import json
import time
import traceback
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv

# --- LOAD ENV & CONFIGURATION ---
load_dotenv()

BASE_REPO = "./juice-shop"
# CRÍTICA APLICADA: Nome do arquivo alterado para refletir o dado real (bruto, não comprimido)
# e salvo na raiz do projeto (./) conforme solicitado.
CVEFIXES_JSON_PATH = "./cvefixes_contexts.json"

TARGET_EXTENSIONS, IGNORE_EXTENSIONS, TARGET_DIRS, IGNORE_DIRS, IGNORE_FILES = get_dirs_and_extensions()

# --- TREE-SITTER SETUP ---
language, parser = get_ts_tree_sitter_language_and_parser()

# --- QDRANT SETUP & BUSCA ---
qdrant_client, sparse_model = get_qdrant_client()

# --- MAIN RETRIEVAL ---
def main():
    # Iniciando a marcação de tempo
    start_time = time.time()
    
    print("\n⚙️ [FASE 1 - CACHE] Iniciando extração de contexto bruto do Qdrant...")

    target_dirs_paths = [Path(BASE_REPO) / d for d in TARGET_DIRS]
    files_to_process = []
    for root, dirs, files in os.walk(BASE_REPO):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        if any(str(Path(root)).startswith(str(t)) for t in target_dirs_paths):
            files_to_process.extend([
                os.path.join(root, f) for f in files 
                if any(f.endswith(ext) for ext in TARGET_EXTENSIONS) and not any(f.endswith(ext) for ext in IGNORE_EXTENSIONS)
            ])

    precomputed_data = {}
    
    print(f"📦 Buscando discussões em vetor para {len(files_to_process)} arquivos...")
    for file_path in tqdm(files_to_process):
        if os.path.basename(file_path) in IGNORE_FILES: continue
        
        rel_path = os.path.relpath(file_path, BASE_REPO)
        precomputed_data[rel_path] = {}
        
        with open(file_path, 'rb') as f: code_bytes = bytearray(f.read())
        functions = extract_functions(code_bytes, language, parser)
        
        processed_hashes = set()
        for func_tuple in functions:
            start, end = func_tuple[0], func_tuple[1]
            original_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
            clean_func_text = sanitize_code_semantics(original_func_text, language, parser)
            
            func_id = get_func_id(clean_func_text)
            if func_id in processed_hashes: continue
            processed_hashes.add(func_id)
            
            try:
                # Recuperação bruta direta
                cvefixes_context = retrieve_from_qdrant(qdrant_client, sparse_model, clean_func_text, limit=1, collection_name="cvefixes_bm25_js_ts")
                
                # Armazena o valor bruto, tratando vazios e nulos
                precomputed_data[rel_path][func_id] = cvefixes_context if cvefixes_context and cvefixes_context.strip() else ""
                
            except Exception as e:
                print(f"\n   ⚠️ Falha Crítica ao buscar {func_id} em {rel_path}:")
                print(traceback.format_exc())
                precomputed_data[rel_path][func_id] = ""
                
    # Salvar em JSON na raiz do projeto
    with open(CVEFIXES_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(precomputed_data, f, indent=4)
        
    # Finalizando a marcação de tempo
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print("\n" + "="*60)
    print(f"💾 Contextos CVEfixes salvos com sucesso em: {CVEFIXES_JSON_PATH}")
    print(f"⏱️  Tempo total de execução do pipeline: {elapsed_time:.2f} segundos ({elapsed_time/60:.2f} minutos)")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()