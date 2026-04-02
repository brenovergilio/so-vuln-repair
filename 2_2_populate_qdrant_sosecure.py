import json
import re
from tqdm import tqdm
from qdrant_client import QdrantClient
from qdrant_client.models import SparseVectorParams, SparseIndexParams, PointStruct, SparseVector
from fastembed import SparseTextEmbedding

# --- Configuration ---
input_file = "sosecure_js_ts_final.jsonl" 
collection_name = "sosecure_bm25_js_ts"
qdrant_host = "localhost"
qdrant_port = 6333
batch_size = 64

print(f"--- Loading Sparse Model (BM25) ---")
# Mantemos apenas o modelo esparso para seguir a metodologia do SOSecure
sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")

print(f"--- Connecting to Qdrant ---")
client = QdrantClient(host=qdrant_host, port=qdrant_port)

# Recriando a coleção APENAS com configuração para vetores esparsos
client.recreate_collection(
    collection_name=collection_name,
    sparse_vectors_config={
        "bm25": SparseVectorParams(index=SparseIndexParams(on_disk=False))
    }
)

def extract_code_blocks(html_body):
    """
    O SOSecure usa apenas o código concatenado para a busca BM25, ignorando o texto em inglês.
    Esta função extrai tudo o que estiver dentro das tags <code> preservadas.
    """
    matches = re.findall(r'<code>(.*?)</code>', html_body, re.DOTALL | re.IGNORECASE)
    return "\n".join(matches).strip()

def process_and_upload_batch(client, collection_name, text_batch, meta_batch):
    try:
        # 1. Gerar apenas Embeddings Esparsos
        sparse_embeddings = list(sparse_model.embed(text_batch))
        
        points = []
        limit = min(len(sparse_embeddings), len(meta_batch))
        
        for j in range(limit):
            sparse = sparse_embeddings[j]
            meta = meta_batch[j]
            
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
            
        # 2. Upload para o Qdrant
        client.upsert(collection_name=collection_name, points=points)
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Failed indexing batch of {len(text_batch)} itens: {e}")
        return False

print(f"--- Starting SOSecure Strict Indexing ---")

batch_texts = []
batch_meta = []
total_lines = sum(1 for _ in open(input_file, 'r', encoding='utf-8'))
saved_vectors = 0
skipped_no_code = 0

with open(input_file, 'r', encoding='utf-8') as f:
    for i, line in enumerate(tqdm(f, total=total_lines, desc="Indexing")):
        try:
            doc = json.loads(line)
            body = doc.get('body', '')
            
            # Extrai estritamente o código para o BM25 indexar
            code_only = extract_code_blocks(body)
            
            # Pula a indexação se a resposta não tiver código, conforme artigo
            if not code_only:
                skipped_no_code += 1
                continue

            payload = {
                "original_id": doc['id'],
                "parent_id": doc.get('parent_id'),
                "body": body, # Salvamos o body completo no payload para recuperar depois
                "comments": doc.get('comments', []),
                "tags": doc.get('tags', []),
                "url": f"https://stackoverflow.com/a/{doc['id']}"
            }
            
            batch_texts.append(code_only)
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

    # Upload do último batch restante
    if batch_texts:
        success = process_and_upload_batch(client, collection_name, batch_texts, batch_meta)
        if success:
            saved_vectors += len(batch_texts)

print("="*40)
print(f"Finished Indexing!")
print(f"Total of saved vectors: {saved_vectors}")
print(f"Answers skipped (no code blocks): {skipped_no_code}")
print("="*40)