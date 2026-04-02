import sqlite3
import csv
import time
import os

# --- CONFIGURAÇÕES ---
DB_PATH = "test_cve_fixes/CVEfixes_v1.0.8/Data/CVEfixes.db"
TINY_DB = "js_ts_minified.db"
CSV_PATH = "ts_js_cvefixes.csv"

def extract_safe_pipe():
    print("🚀 Iniciando a Extração em Tubo (Zero RAM, Zero Cartesian Products)...")
    start_time = time.time()
    
    # Limpa o banco pequeno se existir
    if os.path.exists(TINY_DB):
        os.remove(TINY_DB)
        
    src_conn = sqlite3.connect(DB_PATH)
    dst_conn = sqlite3.connect(TINY_DB)
    
    # 1. Cria as tabelas na nossa base minúscula
    dst_conn.execute("CREATE TABLE files (fc_id INTEGER, hash TEXT, filename TEXT, lang TEXT)")
    dst_conn.execute("CREATE TABLE methods (fc_id INTEGER, name TEXT, before TEXT, code TEXT)")
    dst_conn.execute("CREATE TABLE cves (hash TEXT, cve_id TEXT, cwe_id TEXT)")
    
    # 2. Transporta apenas os ficheiros JS/TS
    print("📂 [1/4] Transportando Ficheiros JavaScript/TypeScript...")
    for row in src_conn.execute("SELECT file_change_id, hash, filename, programming_language FROM file_change WHERE programming_language IN ('JavaScript', 'TypeScript')"):
        dst_conn.execute("INSERT INTO files VALUES (?,?,?,?)", row)
    dst_conn.commit()
    
    # 3. Transporta os mapeamentos de CVE (Isto é leve)
    print("🔗 [2/4] Transportando Mapeamentos de CVE e CWE...")
    for row in src_conn.execute("SELECT f.hash, c.cve_id, cc.cwe_id FROM cve c JOIN fixes f ON c.cve_id = f.cve_id LEFT JOIN cwe_classification cc ON c.cve_id = cc.cve_id"):
        dst_conn.execute("INSERT INTO cves VALUES (?,?,?)", row)
    dst_conn.commit()
    
    # 4. A MAGIA: Transportar os códigos em Lotes!
    print("💻 [3/4] Transportando o Código-Fonte (Em lotes para poupar RAM)...")
    # Busca os IDs dos ficheiros que sabemos ser JS/TS
    fc_ids = [r[0] for r in dst_conn.execute("SELECT fc_id FROM files")]
    
    # O SQLite tem um limite de 999 variáveis por query. Cortamos em lotes de 900.
    lote_size = 900
    total_lotes = (len(fc_ids) // lote_size) + 1
    
    for i in range(0, len(fc_ids), lote_size):
        chunk = fc_ids[i:i+lote_size]
        placeholders = ','.join('?' * len(chunk))
        query = f"SELECT file_change_id, name, before_change, code FROM method_change WHERE file_change_id IN ({placeholders}) AND code IS NOT NULL AND code != ''"
        
        for row in src_conn.execute(query, chunk):
            dst_conn.execute("INSERT INTO methods VALUES (?,?,?,?)", row)
        
        print(f"   -> Lote {(i//lote_size)+1}/{total_lotes} processado...")
    dst_conn.commit()
    
    # 5. Cruzamento final na base minúscula (Rápido e sem quebrar)
    print("🧩 [4/4] Cruzando pares (Streaming contínuo sem GROUP BY) e exportando...")
    
    # Criamos índices na base minúscula para o JOIN ser instantâneo
    dst_conn.execute("CREATE INDEX IF NOT EXISTS idx_f ON files(fc_id)")
    dst_conn.execute("CREATE INDEX IF NOT EXISTS idx_c ON cves(hash)")
    dst_conn.execute("CREATE INDEX IF NOT EXISTS idx_m ON methods(fc_id, name, before)")
    
    # A MÁGICA: Retiramos o GROUP BY. 
    # O SQLite vai "cuspir" as linhas instantaneamente, uma a uma.
    streaming_query = """
    SELECT 
        c.cve_id,
        c.cwe_id,
        f.lang AS programming_language,
        f.filename,
        m_before.name AS function_name,
        m_before.code AS vulnerable_code,
        m_after.code AS fixed_code
    FROM files f
    JOIN cves c ON f.hash = c.hash
    JOIN methods m_before ON f.fc_id = m_before.fc_id 
         AND m_before.before IN ('True', 'true', '1', 1)
    JOIN methods m_after ON f.fc_id = m_after.fc_id 
         AND m_after.before IN ('False', 'false', '0', 0) 
         AND m_before.name = m_after.name
    """
    
    seen_hashes = set()
    rows_written = 0
    
    with open(CSV_PATH, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["cve_id", "cwe_id", "programming_language", "filename", "function_name", "vulnerable_code", "fixed_code"])
        
        # O fetch iterativo funciona como um gerador (batching natural)
        for row in dst_conn.execute(streaming_query):
            cve_id, cwe_id, lang, filename, func_name, vuln, fixed = row
            
            # Limpeza rápida para garantir que espaços invisíveis não enganem o hash
            clean_vuln = str(vuln).strip()
            clean_fixed = str(fixed).strip()
            
            # Filtro 1: Ignora se o código supostamente "corrigido" for exatamente igual ao vulnerável
            if clean_vuln == clean_fixed:
                continue
            
            # Filtro 2 (A SUA IDEIA): Assinatura digital baseada APENAS no código
            # Se o mesmo par de código aparecer noutro CVE ou ficheiro, será ignorado
            row_signature = hash((clean_vuln, clean_fixed))
            
            if row_signature not in seen_hashes:
                seen_hashes.add(row_signature)
                writer.writerow(row)
                rows_written += 1
                
                # Feedback visual
                if rows_written % 100 == 0:
                    print(f"   -> Escritas {rows_written} linhas únicas no CSV...")
            
    # Limpeza
    src_conn.close()
    dst_conn.close()
    if os.path.exists(TINY_DB):
        os.remove(TINY_DB)
    
    elapsed = time.time() - start_time
    print(f"\n✅ VITÓRIA ABSOLUTA! Extração de {rows_written} linhas ÚNICAS concluída em {elapsed:.2f} segundos.")
    print(f"📁 O seu ficheiro final de ouro e ultra-limpo: {CSV_PATH}")

if __name__ == "__main__":
    extract_safe_pipe()