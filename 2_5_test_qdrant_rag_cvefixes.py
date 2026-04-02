import time
from qdrant_client import QdrantClient, models
from fastembed import SparseTextEmbedding

# --- Configuration ---
COLLECTION_NAME = "cvefixes_bm25_js_ts"  # Atualizado para a nossa coleção
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

# --- INPUT: VULNERABLE CODE ---
# Mantivemos um exemplo clássico de SQL Injection em JS/TS
CODE_QUERY = """
const userId = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);
"""

print(f"--- RAG TEST: CODE-TO-CODE SEARCH (CVEfixes) ---")
print("Input Code:")
print(f"--------------------------------------------------")
print(CODE_QUERY.strip())
print(f"--------------------------------------------------\n")

print("Loading model...", end=" ", flush=True)
sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")
print("OK.")

print("Generating code vectors...", end=" ", flush=True)
sparse_generator = sparse_model.embed([CODE_QUERY])
sparse_vector_obj = list(sparse_generator)[0]

# Montando o vetor esparso nativo do Qdrant
sparse_vector = models.SparseVector(
    indices=sparse_vector_obj.indices.tolist(),
    values=sparse_vector_obj.values.tolist()
)
print("OK.")

client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
start_time = time.time()

# Busca direta usando apenas o índice BM25
results = client.query_points(
    collection_name=COLLECTION_NAME,
    query=sparse_vector,
    using="bm25", 
    limit=5, 
)

end_time = time.time()

print(f"\nSearch finished in {end_time - start_time:.4f}s.")
print("=== FOUND VULNERABILITIES (CVEfixes) ===")

for i, hit in enumerate(results.points):
    p = hit.payload or {}
    print(f"\n🔥 MATCH #{i+1} (Score: {hit.score:.4f})")
    
    # Extraindo as chaves específicas do nosso dataset CVEfixes
    print(f"   🛡️ CVE: {p.get('cve_id', 'N/A')} | CWE: {p.get('cwe_id', 'N/A')}")
    print(f"   📁 File: {p.get('filename', 'Unknown')} | Func: {p.get('function_name', 'Unknown')}")
    
    # Formatando o código numa única linha e limitando a 150 caracteres para não poluir o terminal
    vuln_code = str(p.get('vulnerable_code', '')).replace('\n', ' ').strip()
    fixed_code = str(p.get('fixed_code', '')).replace('\n', ' ').strip()
    
    print(f"   ❌ Vulnerable: {vuln_code[:150]}...")
    print(f"   ✅ Fixed:      {fixed_code[:150]}...")
    print("-" * 80)