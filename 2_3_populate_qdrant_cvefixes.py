import csv
import sys
import uuid
import time
from tqdm import tqdm
from qdrant_client import QdrantClient
from qdrant_client.models import SparseVectorParams, SparseIndexParams, PointStruct, SparseVector
from fastembed import SparseTextEmbedding

# --- A MÁGICA PARA O ERRO DO CSV ---
# Aumenta o limite de tamanho de uma única célula do CSV de forma iterativa e segura
maxInt = sys.maxsize
while True:
    try:
        csv.field_size_limit(maxInt)
        break
    except OverflowError:
        maxInt = int(maxInt/10)

# --- Configuration ---
input_file = "ts_js_cvefixes.csv"  
collection_name = "cvefixes_bm25_js_ts"
qdrant_host = "localhost"
qdrant_port = 6333
batch_size = 64

print(f"--- Loading Sparse Model (BM25) ---")
sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")

print(f"--- Connecting to Qdrant ---")
client = QdrantClient(host=qdrant_host, port=qdrant_port)

# Mantido exatamente com o recreate_collection (Warning ignorado)
client.recreate_collection(
    collection_name=collection_name,
    vectors_config={}, 
    sparse_vectors_config={
        "bm25": SparseVectorParams(
            index=SparseIndexParams(on_disk=True) 
        )
    }
)

def process_and_upload_batch(client, collection_name, text_batch, meta_batch):
    try:
        sparse_embeddings = list(sparse_model.embed(text_batch))
        
        points = []
        for sparse, meta in zip(sparse_embeddings, meta_batch):
            points.append(PointStruct(
                id=meta["id"],
                vector={
                    "bm25": SparseVector(
                        indices=sparse.indices.tolist(),
                        values=sparse.values.tolist()
                    )
                },
                payload=meta["payload"]
            ))
            
        client.upsert(collection_name=collection_name, points=points)
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Failed indexing batch of {len(text_batch)} itens: {e}")
        return False

print(f"--- Starting CVEfixes Strict Indexing (Zero RAM Streaming) ---")

batch_texts = []
batch_meta = []
saved_vectors = 0
skipped_no_code = 0
skipped_too_large = 0

with open(input_file, 'r', encoding='utf-8') as f:
    total_lines = sum(1 for _ in f) - 1

with open(input_file, mode='r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    
    for row in tqdm(reader, total=total_lines, desc="Indexing"):
        
        vuln_code = str(row.get('vulnerable_code', '')).strip()
        fixed_code = str(row.get('fixed_code', '')).strip()
        
        if not vuln_code or vuln_code.lower() == 'nan':
            skipped_no_code += 1
            continue

        MAX_CHARS = 50000 
        if len(vuln_code) > MAX_CHARS or len(fixed_code) > MAX_CHARS:
            skipped_too_large += 1 # Não se esqueça de declarar esta variável lá em cima junto com skipped_no_code
            continue

        cwe_id = str(row.get('cwe_id', 'Unknown'))
        if cwe_id.lower() == 'nan' or not cwe_id:
            cwe_id = "Unknown"

        payload = {
            "cve_id": str(row.get('cve_id', 'Unknown')),
            "cwe_id": cwe_id,
            "vulnerable_code": vuln_code,
            "fixed_code": fixed_code,
            "function_name": str(row.get('function_name', 'Unknown')),
            "filename": str(row.get('filename', 'Unknown')),
            "language": str(row.get('programming_language', 'Unknown'))
        }
        
        batch_texts.append(vuln_code)
        
        vec_id = str(uuid.uuid4())
        batch_meta.append({"id": vec_id, "payload": payload})

        if len(batch_texts) >= batch_size:
            success = process_and_upload_batch(client, collection_name, batch_texts, batch_meta)
            if success:
                saved_vectors += len(batch_texts)
            
            batch_texts = []
            batch_meta = []

if batch_texts:
    success = process_and_upload_batch(client, collection_name, batch_texts, batch_meta)
    if success:
        saved_vectors += len(batch_texts)

print("="*40)
print(f"✅ Finished Indexing CVEfixes!")
print(f"📊 Total of saved vectors: {saved_vectors}")
print(f"⏭️ Rows skipped (no vulnerable code): {skipped_no_code}")
print(f"⏭️ Rows skipped (code too large): {skipped_too_large}")
print("="*40)