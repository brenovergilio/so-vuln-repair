import os
from pathlib import Path
from tqdm import tqdm
from transformers import AutoTokenizer
from qdrant_client import QdrantClient, models
from fastembed import SparseTextEmbedding
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser, Query, QueryCursor

# --- CONFIGURAÇÕES ---
BASE_REPO = "./juice-shop"
COLLECTION_NAME = "sosecure_bm25_js_ts"
OUTPUT_REPORT_FILE = "token_analysis_report.txt"

TARGET_EXTENSIONS = {".ts"}
IGNORE_EXTENSIONS = {".spec.ts"}
TARGET_DIRS = {"routes", "models", "frontend/src/app"} 
IGNORE_DIRS = {"node_modules", ".git", "test", "dist", ".angular", "e2e", "vagrant", "assets", "environments"}
IGNORE_FILES = {"verify.ts", "vulnCodeFixes.ts", "vulnCodeSnippet.ts"}

# --- PROMPTS DO SOSECURE ---
PROMPT_SYS = "You are a helpful assistant that generates secure JavaScript/TypeScript code. Please provide all generated code in one code block."

def get_prompt_rag(query, context):
    return f"""Given the following code:

{query}

Does this code have any security vulnerabilities? Below is a related StackOverflow answers and its comments for additional context that may be helpful:
---
{context}
---

**Instructions:**
- Review the code for any security flaws.
- If the code has security issues, modify the code to follow best security practices while ensuring the original functionality and logic are maintained.
- If no security issues are found, output "No security issues found".
- Ensure that the fixes do not alter the original intent of the code.
- It is imperative that the new code should not have any CWE or CVE security errors.
"""


print("⏳ Carregando dependências...")
tokenizer = AutoTokenizer.from_pretrained("unsloth/Meta-Llama-3.1-8B-Instruct")
qdrant_client = QdrantClient(host="localhost", port=6333)
sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")
language = Language(tsts.language_typescript())
parser = Parser(language)
print("✅ Tudo pronto. Iniciando análise de tokens...")

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
        if "challenge" in func_name.lower():
            continue
        funcs.append((node.start_byte, node.end_byte, func_name))
    return funcs

def count_llama_tokens(text: str) -> int:
    return len(tokenizer.encode(text))

def main():
    target_dirs_paths = [Path(BASE_REPO) / d for d in TARGET_DIRS]
    files_to_process = []
    
    for root, dirs, files in os.walk(BASE_REPO):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        if any(str(Path(root)).startswith(str(t)) for t in target_dirs_paths):
            files_to_process.extend([
                os.path.join(root, f) for f in files 
                if any(f.endswith(ext) for ext in TARGET_EXTENSIONS) 
                and not any(f.endswith(ext) for ext in IGNORE_EXTENSIONS)
            ])

    total_functions = 0
    stats = {"safe": 0, "warning": 0, "critical": 0}

    # Abrindo o arquivo para escrita
    with open(OUTPUT_REPORT_FILE, "w", encoding="utf-8") as out_f:
        out_f.write("=== RELATÓRIO DE ANÁLISE DE TOKENS (RAG LIMIT=5) ===\n\n")
        
        # tqdm adicionado para visualização no terminal
        for file_path in tqdm(files_to_process, desc="Analisando arquivos"):
            if os.path.basename(file_path) in IGNORE_FILES: continue
            
            with open(file_path, 'rb') as f: code_bytes = bytearray(f.read())
            functions = extract_functions(code_bytes)
            
            for func_tuple in functions:
                start, end, func_name = func_tuple
                func_name = func_name or "Anonymous_Function"
                clean_func_text = code_bytes[start:end].decode('utf-8', errors='ignore')
                
                # Recuperação Qdrant
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
                    limit=5, # <- LIMIT 5 conforme SOSecure
                )
                
                context_blocks = []
                for hit in results.points:
                    p = hit.payload or {}
                    answer_body = p.get('body', '')
                    comments = p.get('comments', [])
                    block = f"--- Post Answer ---\n{answer_body}\n\nComments:\n" + "\n".join([f"- {c}" for c in comments])
                    context_blocks.append(block)
                    
                raw_context = "\n\n=======================\n\n".join(context_blocks)
                user_content = get_prompt_rag(clean_func_text, raw_context)
                full_prompt = PROMPT_SYS + "\n" + user_content
                
                token_count = count_llama_tokens(full_prompt)
                total_functions += 1
                
                # Lógica de Categorização para o arquivo
                if token_count > 6144:
                    tag = "[CRÍTICO > 6144]"
                    stats["critical"] += 1
                elif token_count > 4096:
                    tag = "[ALERTA  > 4096]"
                    stats["warning"] += 1
                else:
                    tag = "[SEGURO <= 4096]"
                    stats["safe"] += 1
                    
                log_line = f"{tag} {token_count} tokens | {os.path.basename(file_path)} -> {func_name}\n"
                out_f.write(log_line)

        # Escrevendo o resumo final no arquivo
        summary = (
            "\n" + "="*40 + "\n"
            "--- RESUMO GERAL ---\n"
            f"Total de Funções Analisadas: {total_functions}\n"
            f"Seguro (<= 4096)           : {stats['safe']}\n"
            f"Alerta (> 4096 e <= 6144)  : {stats['warning']}\n"
            f"Perigo Crítico (> 6144)    : {stats['critical']}\n"
            + "="*40 + "\n"
        )
        out_f.write(summary)

    # Imprimindo o resumo final no terminal para conveniência
    print(summary)
    print(f"✅ Análise concluída. O relatório detalhado foi salvo em: {OUTPUT_REPORT_FILE}")

if __name__ == "__main__":
    main()