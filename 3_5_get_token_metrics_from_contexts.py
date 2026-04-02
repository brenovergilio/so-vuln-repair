import json
import os
import statistics
from utils import get_llama_tokenizer, count_llama_tokens

# --- CONFIGURATION ---
JSON_FILES = [
    "raw_so_contexts.json",
    "compressed_contexts.json",
    "abstractive_contexts.json",
    "cvefixes_contexts.json",
]

def count_llama_tokens(text: str, tokenizer) -> int:
    if not text or tokenizer is None:
        return 0
    return len(tokenizer.encode(text))

def analyze_json_tokens(file_path: str, tokenizer):
    """
    Lê um ficheiro JSON e calcula as estatísticas reais de tokens
    usando o tokenizador nativo do Llama.
    """
    if not os.path.exists(file_path):
        print(f"❌ O ficheiro '{file_path}' não existe. Saltando...")
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        token_counts = []
        
        for file_key, hash_dict in data.items():
            for hash_key, input_text in hash_dict.items():
                num_tokens = count_llama_tokens(input_text, tokenizer)
                token_counts.append(num_tokens)
                
        if not token_counts:
            print(f"⚠️ O ficheiro '{file_path}' está vazio ou não contém inputs válidos.")
            return
            
        min_tokens = min(token_counts)
        max_tokens = max(token_counts)
        avg_tokens = statistics.mean(token_counts)
        
        print(f"✅ Estatísticas para '{file_path}' (Total de entradas: {len(token_counts)}):")
        print(f"   -> Mínimo de tokens: {min_tokens}")
        print(f"   -> Médio de tokens:  {avg_tokens:.2f}")
        print(f"   -> Máximo de tokens: {max_tokens}")
        print("-" * 50)
        
    except json.JSONDecodeError:
        print(f"❌ Erro: O ficheiro '{file_path}' não é um JSON válido.")
    except Exception as e:
        print(f"❌ Ocorreu um erro ao processar '{file_path}': {e}")

# --- EXECUTION ---
if __name__ == "__main__":
    print("=" * 50)
    print("🧠 RAG CONTEXTS TOKEN ANALYZER")
    print("=" * 50)
    tokenizer = get_llama_tokenizer()
    
    try:
        for json_file in JSON_FILES:
            analyze_json_tokens(json_file, tokenizer)
            
    except Exception as e:
        print(f"❌ Falha ao carregar o tokenizador: {e}")
        print("Dica: Se estiver a usar o repositório oficial da Meta, precisa de estar autenticado com o Hugging Face CLI (huggingface-cli login).")