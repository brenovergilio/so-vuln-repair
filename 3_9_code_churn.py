import os
import glob
import difflib
import csv

# --- CONFIGURAÇÕES ---
# Procura nas pastas oci ou local, ignorando pastas de logs ou reports
SEARCH_PATTERN = "./experiment_results/*/juice-shop/*"
BASELINE_REPO = "./juice-shop"  # Caminho para o Juice Shop original (intacto)
OUTPUT_CSV = "./experiment_results/patch_metrics.csv"

def count_diff_lines(baseline_file, target_file):
    """
    Compara dois ficheiros e retorna o número de linhas adicionadas e removidas.
    """
    with open(baseline_file, 'r', encoding='utf-8', errors='ignore') as f1, \
         open(target_file, 'r', encoding='utf-8', errors='ignore') as f2:
        lines1 = f1.readlines()
        lines2 = f2.readlines()

    # Se forem exatamente iguais, poupamos processamento
    if lines1 == lines2:
        return 0, 0

    added = 0
    removed = 0
    
    # n=0 significa que não queremos linhas de contexto, apenas as que mudaram
    diff = difflib.unified_diff(lines1, lines2, n=0)
    
    for line in diff:
        # Ignora os cabeçalhos do diff (+++ e ---)
        if line.startswith('+++') or line.startswith('---'):
            continue
        if line.startswith('+'):
            added += 1
        elif line.startswith('-'):
            removed += 1
            
    return added, removed

def get_target_repositories():
    repos = []
    for path in glob.glob(SEARCH_PATTERN):
        if os.path.isdir(path) and not path.endswith("_logs") and not path.endswith("reports"):
            # Evita pastas como "baseline-original" se estiverem na pasta de resultados
            if "baseline-original" not in path:
                repos.append(os.path.normpath(path))
    return sorted(repos)

def analyze_repository_churn(repo_path, baseline_path):
    """
    Percorre o repositório, encontra ficheiros .ts e compara com o baseline.
    """
    files_changed = 0
    total_added = 0
    total_removed = 0
    
    # Procura recursivamente todos os ficheiros TypeScript
    ts_files = glob.glob(os.path.join(repo_path, '**', '*.ts'), recursive=True)
    
    for target_file in ts_files:
        # Ignora a pasta node_modules para não travar o script
        if 'node_modules' in target_file:
            continue
            
        # Constrói o caminho relativo para encontrar o ficheiro correspondente no baseline
        rel_path = os.path.relpath(target_file, repo_path)
        baseline_file = os.path.join(baseline_path, rel_path)
        
        if os.path.exists(baseline_file):
            added, removed = count_diff_lines(baseline_file, target_file)
            
            if added > 0 or removed > 0:
                files_changed += 1
                total_added += added
                total_removed += removed
                print(f"      📝 Modificado: {rel_path} (+{added} / -{removed})")
        else:
            # Ficheiro novo criado pelo LLM (Alucinação arquitetural?)
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                added = len(f.readlines())
            files_changed += 1
            total_added += added
            print(f"      ✨ Novo Ficheiro: {rel_path} (+{added})")

    return files_changed, total_added, total_removed

if __name__ == "__main__":
    if not os.path.exists(BASELINE_REPO):
        print(f"❌ ERRO: O repositório base '{BASELINE_REPO}' não foi encontrado.")
        exit(1)

    repositories = get_target_repositories()
    
    if not repositories:
        print("❌ Nenhum repositório modificado encontrado.")
        exit(1)

    print(f"🔍 Iniciando Análise de Code Churn em {len(repositories)} repositórios...")
    
    # Prepara o ficheiro CSV
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    with open(OUTPUT_CSV, 'w', encoding='utf-8', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Repository", "Files_Modified", "Lines_Added", "Lines_Removed", "Total_Churn"])
        
        for repo in repositories:
            repo_name = os.path.basename(repo)
            print(f"\n📊 Analisando: {repo_name}")
            
            files_changed, added, removed = analyze_repository_churn(repo, BASELINE_REPO)
            total_churn = added + removed
            
            print(f"   📈 Resumo {repo_name}: {files_changed} ficheiros | +{added} | -{removed} | Churn: {total_churn}")
            
            writer.writerow([repo_name, files_changed, added, removed, total_churn])

    print("\n" + "="*60)
    print(f"🎉 Análise Concluída! Os resultados foram salvos em: {OUTPUT_CSV}")
    print("="*60)