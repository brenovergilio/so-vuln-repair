from utils import get_dirs_and_extensions, get_func_id, get_qdrant_client, get_ts_tree_sitter_language_and_parser, sanitize_code_semantics, extract_functions, retrieve_from_qdrant
import os
import gc
import json
import time
import traceback
import torch
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()

BASE_REPO = "./juice-shop"
PROVIDER = os.getenv("PROVIDER", "local")

PRECOMPUTED_JSON_PATH = "./compressed_contexts2.json"

TARGET_EXTENSIONS, IGNORE_EXTENSIONS, TARGET_DIRS, IGNORE_DIRS, IGNORE_FILES = get_dirs_and_extensions()

language, parser = get_ts_tree_sitter_language_and_parser()

qdrant_client, sparse_model = get_qdrant_client()

def main():
    start_time = time.time()
    
    print(f"\n⚙️ [FASE 1] Iniciando pré-computação com LongLLMLingua (Provider: {PROVIDER})...")
    
    try:
        from llmlingua import PromptCompressor
        print("📥 Configurando LongLLMLingua (Llama-2/Causal LM)...")
        
        compressor = PromptCompressor(
            model_name="NousResearch/Llama-2-7b-hf", 
            device_map="cuda"
        )
        print("✅ LongLLMLingua carregado com sucesso!")
    except Exception as e:
        print(f"❌ Falha ao iniciar compressor: {e}\n{traceback.format_exc()}")
        return

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
    
    print(f"📦 Comprimindo fóruns para {len(files_to_process)} arquivos...")
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
            
            raw_context = retrieve_from_qdrant(qdrant_client, sparse_model, clean_func_text, limit=5)
            
            if not raw_context or not raw_context.strip():
                precomputed_data[rel_path][func_id] = ""
                continue
                
            try:
                
                instruction_str = "Review the StackOverflow discussions and extract security vulnerability fixes."
                question_str = f"Does this code have any security vulnerabilities?\n{clean_func_text}"
                
                compressed_results = compressor.compress_prompt(
                    context=[raw_context], 
                    instruction=instruction_str,
                    question=question_str,
                    target_token=1000,
                    condition_in_question="after_condition",
                    reorder_context="sort_based",
                    dynamic_context_compression_ratio=0.3,
                    condition_compare=True,
                    rank_method="longllmlingua"
                )
                precomputed_data[rel_path][func_id] = compressed_results['compressed_prompt']
            except Exception as e:
                print(f"\n   ⚠️ Falha Crítica ao comprimir {func_id} em {rel_path}:")
                print(traceback.format_exc())
            finally:
                
                gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                
    with open(PRECOMPUTED_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(precomputed_data, f, indent=4)
        
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print("\n" + "="*60)
    print(f"💾 Compressões salvas em: {PRECOMPUTED_JSON_PATH}")
    print(f"⏱️ Tempo total de execução (Recuperação + Compressão): {elapsed_time:.2f} segundos ({elapsed_time/60:.2f} minutos)")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()