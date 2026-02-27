import sqlite3
import json
import re
import os
from bs4 import BeautifulSoup
from tqdm import tqdm

# --- Configuration ---
posts_file = "data-filtering-scripts/so_security_posts.jsonl"
comments_file = "data-filtering-scripts/so_security_comments.jsonl"
output_file = "sosecure_js_ts_final.jsonl"
db_file = "data-filtering-scripts/temp_production.db"

# 1. What we want (Whitelist)
TARGET_TAGS = {
    "javascript", "typescript", "node.js", "angular", "angularjs", "reactjs", "vue.js",
    "express", "mean-stack", "sequelize", "typeorm", "nestjs", "electron", "ecmascript"
}

# 2.What we don't want (Blacklist)
EXCLUDE_TAGS = {
    "java", "c#", "php", "python", ".net", "c++", "ruby", "go", "android", "ios", 
    "swift", "r", "c", "asp.net", "laravel", "django", "spring", "flask"
}

# 3.Security-related Keywords
SECURITY_WARNING_KEYWORDS = {
    "vulnerable", "vulnerability", "unsafe", "insecure", "security risk",
    "security flaw", "attack", "exploit", "injection", "xss", "csrf", 
    "sanitiz", "malicious", "hacker", "compromise", "leak", "sensitive",
    "do not use", "avoid using", "dangerous", "eval is evil", "weakness",
    "man-in-the-middle", "mitm", "dos", "denial of service", "hijack", "idor",
    "cve", "rce", "cwe", "not safe"
}

def full_clean_text(text):
    if not text: return "", False
    
    # 1. Anonimização
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL]', text)
    text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '[URL]', text)

    soup = BeautifulSoup(text, "html.parser")
    
    # 2. Verificação de existência de código (ESTRITAMENTE <code>, conforme SOSecure)
    code_blocks = soup.find_all('code')
    has_code = bool(code_blocks)
    
    if not has_code:
        return "", False
        
    # 3. Limpeza Customizada: Remover tudo, exceto <code>
    for code_node in code_blocks:
        original_content = str(code_node)
        code_node.replace_with(f"__START_CODE_TAG__{original_content}__END_CODE_TAG__")

    clean_text_with_placeholders = soup.get_text(separator=" ", strip=True)
    
    # Restauramos as tags HTML do código
    final_text = clean_text_with_placeholders.replace("__START_CODE_TAG__", "").replace("__END_CODE_TAG__", "")
    
    final_text = re.sub(r' {2,}', ' ', final_text)

    return final_text, True

print("--- Starting Pipeline ---")

if os.path.exists(db_file):
    os.remove(db_file)

conn = sqlite3.connect(db_file)
c = conn.cursor()

c.execute("PRAGMA synchronous = OFF")
c.execute("PRAGMA journal_mode = MEMORY")
c.execute('''CREATE TABLE posts (id INTEGER PRIMARY KEY, parent_id INTEGER, type INTEGER, json_data TEXT)''')
c.execute('''CREATE TABLE comments (id INTEGER PRIMARY KEY, post_id INTEGER, json_data TEXT)''')

print(f"1. Importing Posts...")
batch = []
with open(posts_file, 'r', encoding='utf-8') as f:
    for line in tqdm(f):
        try:
            d = json.loads(line)
            pid = d.get('parent_id')
            pid = int(pid) if pid else None
            batch.append((int(d['id']), pid, int(d['type']), line))
            if len(batch) >= 50000:
                c.executemany("INSERT OR IGNORE INTO posts VALUES (?, ?, ?, ?)", batch)
                batch = []
        except: pass
if batch: c.executemany("INSERT OR IGNORE INTO posts VALUES (?, ?, ?, ?)", batch)

print(f"2. Importing Comments...")
batch = []
with open(comments_file, 'r', encoding='utf-8') as f:
    for line in tqdm(f):
        try:
            d = json.loads(line)
            batch.append((int(d['id']), int(d['post_id']), line))
            if len(batch) >= 50000:
                c.executemany("INSERT OR IGNORE INTO comments VALUES (?, ?, ?)", batch)
                batch = []
        except: pass
if batch: c.executemany("INSERT OR IGNORE INTO comments VALUES (?, ?, ?)", batch)

print("Indexing SQLite...")
c.execute("CREATE INDEX idx_posts_type ON posts(type)")
c.execute("CREATE INDEX idx_posts_parent ON posts(parent_id)")
c.execute("CREATE INDEX idx_comments_post_id ON comments(post_id)")
conn.commit()

#Só será necesário se voltar a utilzar posts do tipo 1 (questões)
#print("3. Mapeando Tags das Perguntas...")
#valid_parents_tags = {}
#c.execute("SELECT id, json_data FROM posts WHERE type = 1")
#for row in c:
#    d = json.loads(row[1])
#    tags_raw = d.get('tags', [])
#    tags_set = set(tags_raw)
#    
#    if (tags_set & TARGET_TAGS) and not (tags_set & EXCLUDE_TAGS):
#        valid_parents_tags[row[0]] = list(tags_set)
#
#print(f"   -> Perguntas JS Válidas: {len(valid_parents_tags)}")

# --- 3. FILTRAGEM E LIMPEZA FINAL ---
print("4. Processando Respostas e Limpando Texto...")
saved_count = 0

with open(output_file, 'w', encoding='utf-8') as out:
    # Cursor iterador para economizar RAM
    c.execute("SELECT id, parent_id, json_data FROM posts WHERE type = 2")
    
    for row in tqdm(c, desc="Filtrando"):
        post_id = row[0]
        parent_id = row[1]
        
        # [OTIMIZAÇÃO] Passo 1: Checagem barata de Inteiro (Memória)
        #descomentar se voltar a utililizar posts do tipo 1
        #parent_tags = valid_parents_tags.get(parent_id)
        #if not parent_tags:
        #    continue

        # [Optimization] Step 1: Check comments keywords
        cur_comments = conn.cursor()
        cur_comments.execute("SELECT json_data FROM comments WHERE post_id = ?", (post_id,))

        raw_comments = [json.loads(r[0])['text'] for r in cur_comments]
        
        if not raw_comments:
            continue

        has_warning = False
        for comm in raw_comments:
            if any(kw in comm.lower() for kw in SECURITY_WARNING_KEYWORDS):
                has_warning = True
                break
        
        if not has_warning:
            continue

        # [Optimization] Step 2: Full clean text
        post_json = json.loads(row[2])
        clean_body, has_code = full_clean_text(post_json.get('body', ''))
        
        if not has_code:
            continue
            
        clean_title, _ = full_clean_text(post_json.get('title', ''))
        
        final_obj = {
            "id": post_id,
            "parent_id": parent_id,
            "title": clean_title,
            "body": clean_body,
            #"tags": parent_tags,
            "comments": raw_comments,
            "score": post_json.get('score'),
            "url": f"https://stackoverflow.com/a/{post_id}"
        }
        out.write(json.dumps(final_obj) + '\n')
        saved_count += 1

conn.close()
os.remove(db_file)

print("="*40)
print(f"Success! Generated file: {output_file}")
print(f"Total of saved items: {saved_count}")
print("="*40)