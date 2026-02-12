import json
from tqdm import tqdm
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, SparseVectorParams, SparseIndexParams, PointStruct, SparseVector
from sentence_transformers import SentenceTransformer
from fastembed import SparseTextEmbedding

# --- Configuration ---
input_file = "sosecure_js_ts_final.jsonl" 
collection_name = "sosecure_hybrid_js"
qdrant_host = "localhost"
qdrant_port = 6333
batch_size = 64

print(f"--- Loading Models ---")
dense_model = SentenceTransformer('all-MiniLM-L6-v2') 
sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")

print(f"--- Connecting to Qdrant ---")
client = QdrantClient(host=qdrant_host, port=qdrant_port)

client.recreate_collection(
    collection_name=collection_name,
    vectors_config={
        "dense": VectorParams(size=384, distance=Distance.COSINE)
    },
    sparse_vectors_config={
        "sparse": SparseVectorParams(index=SparseIndexParams(on_disk=False))
    }
)

def process_and_upload_batch(client, collection_name, text_batch, meta_batch):
    try:
        # 1. Generate Embeddings
        dense_embeddings = dense_model.encode(text_batch)
        sparse_embeddings = list(sparse_model.embed(text_batch))
        
        points = []
        limit = min(len(dense_embeddings), len(sparse_embeddings), len(meta_batch))
        
        for j in range(limit):
            dense = dense_embeddings[j]
            sparse = sparse_embeddings[j]
            meta = meta_batch[j]
            
            points.append(PointStruct(
                id=meta["id"],
                vector={
                    "dense": dense.tolist(),
                    "sparse": SparseVector(
                        indices=sparse.indices.tolist(),
                        values=sparse.values.tolist()
                    )
                },
                payload=meta["payload"]
            ))
            
        # 2. Upload to Qdrant
        client.upsert(collection_name=collection_name, points=points)
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Failed indexing batch of {len(text_batch)} itens: {e}")
        return False

print(f"--- Starting Hybrid Indexing ---")

batch_texts = []
batch_meta = []
total_lines = sum(1 for _ in open(input_file, 'r', encoding='utf-8'))
saved_vectors = 0

with open(input_file, 'r', encoding='utf-8') as f:
    for i, line in enumerate(tqdm(f, total=total_lines, desc="Indexing")):
        try:
            doc = json.loads(line)
            # add se voltar a usar questions: text_to_embed = f"{doc.get('title', '')}\n{doc.get('body', '')}"

            text_to_embed = f"{doc.get('body', '')}"
            payload = {
                "original_id": doc['id'],
                "parent_id": doc.get('parent_id'),
                #"title": doc.get('title', ''),
                "body": doc.get('body', ''),
                "comments": doc.get('comments', []),
                "tags": doc.get('tags', []),
                "url": f"https://stackoverflow.com/a/{doc['id']}"
            }
            
            batch_texts.append(text_to_embed)
            try:
                vec_id = int(doc['id'])
            except:
                vec_id = i
                
            batch_meta.append({"id": vec_id, "payload": payload})
            
        except json.JSONDecodeError:
            continue

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
print(f"Finished Indexing!")
print(f"Total of saved vectors: {saved_vectors}")
print("="*40)