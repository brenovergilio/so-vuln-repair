from utils import get_dirs_and_extensions, get_func_id, get_qdrant_client, get_ts_tree_sitter_language_and_parser, sanitize_code_semantics, extract_functions, retrieve_from_qdrant
import os
import json
import time
import traceback
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv

from llm_client import LLMClient

load_dotenv()

BASE_REPO = "./juice-shop"
PROVIDER = "compressor"

PRECOMPUTED_JSON_PATH = "./abstractive_contexts.json"

TARGET_EXTENSIONS, IGNORE_EXTENSIONS, TARGET_DIRS, IGNORE_DIRS, IGNORE_FILES = get_dirs_and_extensions()

language, parser = get_ts_tree_sitter_language_and_parser()

qdrant_client, sparse_model = get_qdrant_client()

SYS_PROMPT = """You are an expert cybersecurity context extractor. 
Your task is to compress StackOverflow discussions into concise, dense summaries focused ONLY on security fixes, vulnerabilities, and best practices.
DO NOT hallucinate. DO NOT write code that is not present in the discussion. 
If the discussion does not mention security, reply with 'No security context found.'"""

def get_summarization_prompt(raw_context: str, clean_func_text: str) -> str:
    return f"""Target Function to evaluate later:
{clean_func_text}

Analyze the following forum discussion and extract the core security advice and code snippets that are relevant to the target function above.
    
Discussion:
{raw_context}

Provide a concise summary of the security fixes:"""

def main():
    start_time = time.time()
    
    print(f"\n⚙️ [FASE 1] Iniciando Sumarização Abstrativa via LLM (Provider: {PROVIDER})...")
    
    try:
        llm_compressor = LLMClient(provider=PROVIDER)
        print("✅ Cliente Ollama para Sumarização carregado com sucesso!")
    except Exception as e:
        print(f"❌ Falha ao iniciar cliente LLM: {e}\n{traceback.format_exc()}")
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
    
    print(f"📦 Sumarizando fóruns para {len(files_to_process)} arquivos...")
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
                user_prompt = get_summarization_prompt(raw_context, clean_func_text)
                
                response = llm_compressor.generate_completion(SYS_PROMPT, user_prompt)
                
                if response and isinstance(response, dict) and "text" in response:
                    summary = response["text"].strip()
                    if "No security context found" in summary:
                        summary = ""
                    precomputed_data[rel_path][func_id] = summary
                else:
                    precomputed_data[rel_path][func_id] = ""
                    
            except Exception as e:
                print(f"\n   ⚠️ Falha Crítica ao sumarizar {func_id} em {rel_path}:")
                print(traceback.format_exc())
                precomputed_data[rel_path][func_id] = ""
                
    with open(PRECOMPUTED_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(precomputed_data, f, indent=4)
        
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print("\n" + "="*60)
    print(f"💾 Sumários salvos em: {PRECOMPUTED_JSON_PATH}")
    print(f"⏱️ Tempo total de execução (Recuperação + Sumarização): {elapsed_time:.2f} segundos ({elapsed_time/60:.2f} minutos)")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()