import time
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer
from fastembed import SparseTextEmbedding

# --- Configuration ---
COLLECTION_NAME = "sosecure_hybrid_js"
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

# --- INPUT: VULNERABLE CODE (Simulating Juice Shop) ---
# Example: SQL Injection via string concatenation
CODE_QUERY = """
const userId = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);
"""

print(f"--- RAG TEST: CODE-TO-CODE SEARCH ---")
print("Input Code:")
print(f"--------------------------------------------------")
print(CODE_QUERY.strip())
print(f"--------------------------------------------------\n")

print("Loading models...", end=" ", flush=True)
dense_model = SentenceTransformer('all-MiniLM-L6-v2')
sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")
print("OK.")

print("Generating code vectors...", end=" ", flush=True)

dense_vector = dense_model.encode(CODE_QUERY).tolist()
sparse_generator = sparse_model.embed([CODE_QUERY])
sparse_vector_obj = list(sparse_generator)[0]
sparse_vector = models.SparseVector(
    indices=sparse_vector_obj.indices.tolist(),
    values=sparse_vector_obj.values.tolist()
)
print("OK.")

client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
start_time = time.time()

results = client.query_points(
    collection_name=COLLECTION_NAME,
    prefetch=[
        models.Prefetch(
            query=dense_vector,
            using="dense",
            limit=50, 
        ),
        models.Prefetch(
            query=sparse_vector,
            using="sparse",
            limit=50,
        ),
    ],
    # RRF (Reciprocal Rank Fusion)
    query=models.FusionQuery(fusion=models.Fusion.RRF), 
    limit=5,
)

end_time = time.time()

print(f"\nSearch finished in {end_time - start_time:.4f}s.")
print("=== FOUND ANTIPATTERNS ===")

for i, hit in enumerate(results.points):
    p = hit.payload or {}
    print(f"\n🔥 MATCH #{i+1} (Score: {hit.score:.4f})")
    #print(f"   Título: {p.get('title')}")
    print(f"   URL: {p.get('url')}")
    
    comments = p.get('comments', [])
    print(f"   💬 What community said:")
    for j, comm in enumerate(comments[:2]):
        clean_comm = " ".join(comm.split())
        print(f"      - \"{clean_comm[:200]}...\"")
        
    code_snippet = p.get('body', '')[:150].replace('\n', ' ')
    print(f"   💻 Similar code: {code_snippet}...")
    print("-" * 60)