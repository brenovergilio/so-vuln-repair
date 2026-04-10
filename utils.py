import re
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser, Query, QueryCursor
from transformers import AutoTokenizer
from qdrant_client import QdrantClient, models
from fastembed import SparseTextEmbedding
import hashlib
import requests
import subprocess
import sys
import os

def get_llama_tokenizer():
  print("⏳ Loading Llama 3.1 Tokenizer...")
  try:
      return AutoTokenizer.from_pretrained("unsloth/Meta-Llama-3.1-8B-Instruct")
  except Exception as e:
      print(f"❌ Error loading tokenizer: {e}")
      return None
    
def get_qdrant_client():
  print("⏳ Loading Qdrant (BM25)...")
  try:
    qdrant_client = QdrantClient(host="localhost", port=6333)
    sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")
    
    return qdrant_client, sparse_model 
  except Exception as e:
    print(f"❌ Error loading Qdrant: {e}")
    return None, None
  
def get_dirs_and_extensions():
  return [{".ts"}, # TARGET_EXTENSIONS
        {".spec.ts"}, # IGNORE_EXTENSIONS
        {"routes", "models"}, # TARGET_DIRS
        {"node_modules", ".git", "test", "dist", ".angular", "e2e", "vagrant", "assets", "environments", "frontend"}, # IGNORE_DIRS
        {"verify.ts", "vulnCodeFixes.ts", "vulnCodeSnippet.ts"}] # IGNORE_FILES
# FIX: flag de controle para emitir o aviso de tokenizer nulo apenas uma vez,
#      evitando spam no log e tornando a falha visível sem interromper a execução
_tokenizer_warning_emitted = False
 
def count_llama_tokens(text: str, tokenizer) -> int:
    global _tokenizer_warning_emitted
    if not text:
        return 0
    # FIX: tokenizer None retornava 0 silenciosamente, corrompendo todas as métricas
    if tokenizer is None:
        if not _tokenizer_warning_emitted:
            print("⚠️  AVISO: tokenizer é None — contagens de tokens serão 0. Métricas de custo estarão incorretas.")
            _tokenizer_warning_emitted = True
        return 0
    return len(tokenizer.encode(text))
  
def count_syntax_errors(tree, language=None, parser=None):
    """
    Varre a árvore manualmente para capturar tanto nós de ERRO explícito
    quanto nós AUSENTES (ex: chaves '}' ou ponto e vírgula ';' esquecidos pelo LLM).
    """
    error_count = 0
    
    def walk(node):
        nonlocal error_count
        # Contabiliza se for um erro de sintaxe ou um token esquecido (missing)
        if node.type == 'ERROR' or node.is_missing:
            error_count += 1
            
        # Continua a busca recursiva em todos os filhos
        for child in node.children:
            walk(child)
            
    walk(tree.root_node)
    return error_count

def run_tsc_check(dest_path):
    """
    Roda o TypeScript Compiler (tsc) na raiz do projeto e recolhe TODOS os erros
    de compilação gerados, garantindo que o patch não quebrou outros arquivos em cascata.
    """
    tsc_bin = os.path.join("node_modules", "typescript", "bin", "tsc")
    try:
        result = subprocess.run(
            ["node", tsc_bin, "--noEmit"],
            cwd=dest_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        output = result.stdout
        return_code = result.returncode
    except FileNotFoundError:
        # FIX: 'npx' não encontrado retornava ([], 0), aceitando todos os patches
        #      sem nenhuma validação real. Agora propaga o erro explicitamente.
        msg = "FATAL: 'npx' não encontrado no PATH. Verifique a instalação do Node.js."
        print(f"❌ {msg}")
        return [msg], 1
    except Exception as e:
        # FIX: outros erros de subprocess também geravam output sem "error TS",
        #      fazendo run_tsc_check retornar 0 erros incorretamente
        msg = f"FATAL: Falha ao executar tsc: {e}"
        print(f"❌ {msg}")
        return [msg], 1
 
    global_errors = []
    for line in output.splitlines():
        if "error TS" in line:
            global_errors.append(line.strip())
 
    # FIX: tsc pode falhar por razões não-TS (ex: tsconfig.json ausente) sem gerar
    #      linhas "error TS" — nesse caso o returncode != 0 é o único sinal de falha
    if return_code != 0 and not global_errors:
        fallback_msg = f"tsc encerrou com código {return_code} mas nenhum erro TS foi parseado. Output: {output.strip()[:300]}"
        print(f"⚠️  {fallback_msg}")
        return [fallback_msg], 1
 
    return global_errors, len(global_errors)

def sanitize_code_semantics(text: str, language, parser) -> str:
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
 
    # FIX: set() em nós do tree-sitter depende de __hash__ não garantido entre versões.
    #      Deduplicação explícita por start_byte é segura e determinística.
    seen_starts = set()
    unique_nodes = []
    for n in nodes_to_remove:
        if n.start_byte not in seen_starts:
            seen_starts.add(n.start_byte)
            unique_nodes.append(n)
    nodes_to_remove = sorted(unique_nodes, key=lambda n: n.start_byte, reverse=True)
 
    for node in nodes_to_remove:
        del text_bytes[node.start_byte:node.end_byte]
 
    return text_bytes.decode('utf-8').strip()

def extract_functions(code_bytes, language, parser):
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

def clean_llm_response(response, original_code):
    if not response: return original_code
    
    # Extrai estritamente o código que a IA jogou no Markdown
    match = re.search(r'```(?:javascript|typescript|js|ts)?\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
    cleaned = match.group(1).strip() if match else response.strip()
    
    # Adicionado fallback caso o modelo retorne a mensagem de que não encontrou problemas
    if "No security issues found" in cleaned:
        return original_code.strip()
    
    # Previne a alucinação extra da IA onde ela as vezes retorna os prompts junto com a resposta
    cleaned = re.sub(r'^(CODE TO FIX:|COMMUNITY SECURITY DISCUSSION:)\s*', '', cleaned, flags=re.IGNORECASE).strip()
    
    return cleaned

def calculate_cost_oci(total_chars):
    OCI_PRICE_PER_10K_CHARS = 0.0018
    return (total_chars / 10000.0) * OCI_PRICE_PER_10K_CHARS
  
def get_ts_tree_sitter_language_and_parser():
  language = Language(tsts.language_typescript())
  parser = Parser(language)
  
  return language, parser

from qdrant_client import models

def retrieve_from_qdrant(qdrant_client, sparse_model, clean_func_text, limit=5, collection_name="sosecure_bm25_js_ts"):
    try:
        # 1. Geração do vetor BM25
        sparse_generator = sparse_model.embed([clean_func_text])
        sparse_vector_obj = list(sparse_generator)[0]
        sparse_vector = models.SparseVector(
            indices=sparse_vector_obj.indices.tolist(),
            values=sparse_vector_obj.values.tolist()
        )
                                
        # 2. Busca no Qdrant
        results = qdrant_client.query_points(
            collection_name=collection_name,
            query=sparse_vector,
            using="bm25",
            limit=limit, 
        )
                                
        context_blocks = []
        for hit in results.points:
            p = hit.payload or {}
            
            # 3. Roteamento de Formatação (CVEfixes vs SOSecure)
            if "cvefixes" in collection_name.lower():
                # Formatação estrita para Code-to-Code RAG
                vuln_code = str(p.get('vulnerable_code', '')).strip()
                fixed_code = str(p.get('fixed_code', '')).strip()
                cve_id = p.get('cve_id', 'Unknown')
                cwe_id = p.get('cwe_id', 'Unknown')
                
                block = f"--- Related Vulnerability Pattern ({cve_id} | CWE: {cwe_id}) ---\n"
                block += f"[VULNERABLE CODE]\n{vuln_code}\n\n"
                block += f"[SECURE FIX]\n{fixed_code}"
                context_blocks.append(block)
                
            else:
                # Formatação clássica para o SOSecure (Stack Overflow)
                answer_body = p.get('body', '')
                comments = p.get('comments', [])
                
                block = f"--- Post Answer ---\n{answer_body}\n\nComments:\n"
                block += "\n".join([f"- {c}" for c in comments])
                context_blocks.append(block)
        
        # 4. Junção dos blocos recuperados
        if context_blocks:        
            return "\n\n=======================\n\n".join(context_blocks)
        return ""
        
    except Exception as e:
        print(f"   ⚠️ RAG Retrieval failed: {e}")
        return ""

def get_func_id(func_text: str) -> str:
    """Gera um Hash determinístico da função para ser usado como chave no JSON."""
    return hashlib.md5(func_text.encode('utf-8')).hexdigest()

def get_type_aware_context(file_path: str, clean_func_text = "") -> str:
    """
    Consulta o microserviço Node.js para extrair as assinaturas de tipo
    (Type-Aware Context) do arquivo alvo.
    """
    try:
        url = "http://localhost:3001/extract-types" 
        payload = {
            "filePath": file_path,
            "functionText": clean_func_text  # <-- Injetamos o código aqui
        }
        response = requests.post(url, json=payload, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            type_context = data.get("type_context", "")
            if type_context:
                return f"[LIBRARY SIGNATURES (Type-Aware Context)]\n{type_context}\n\n"
        return ""
        
    except requests.exceptions.RequestException as e:
        sys.exit(f"⚠️ Aviso: Falha ao contactar o Type-Extractor. Ignorando tipagem profunda. Erro: {e}")