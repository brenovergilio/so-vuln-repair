import os
import glob
import re
import subprocess
import shutil
import csv
from collections import Counter

# --- CONFIGURAÇÕES ---
SEARCH_PATTERN = "./experiment_results/*/juice-shop/*"
BASELINE_REPO = "./juice-shop"  # <--- PREENCHER COM O CAMINHO CORRETO
BUILD_COMMAND = ["npm", "run", "build:server"]

# Regex para métricas e captura de ficheiros
TS_ALL_REGEX = re.compile(r"error (TS\d+):")
TS_FILE_ERROR_REGEX = re.compile(r"^(.+?)\((\d+),\d+\):\s*error\s+(TS\d+):", re.MULTILINE)

# ==========================================
# FUNÇÃO AUXILIAR DE CATEGORIZAÇÃO DE ERRO
# ==========================================
def is_syntax_error(ts_code):
    """Verifica se o erro é fatal de sintaxe (TS1000 - TS1999)."""
    try:
        error_num = int(ts_code.replace("TS", ""))
        return 1000 <= error_num <= 1999
    except:
        return False

# ==========================================
# FASE 1: EXTRAÇÃO E MAPEMENTO
# ==========================================
def run_build(repo_path):
    """Executa o comando de build e retorna a saída do terminal."""
    process = subprocess.run(
        BUILD_COMMAND, cwd=repo_path, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True
    )
    return process.stdout, process.returncode

def update_error_csv(repo_path, output_pre):
    """Atualiza o CSV com a contagem exata de erros gerados pelo LLM."""
    logs_dir = f"{repo_path}_logs"
    os.makedirs(logs_dir, exist_ok=True)
    csv_path = os.path.join(logs_dir, "tsc_errors.csv")
    
    new_errors = TS_ALL_REGEX.findall(output_pre)
    new_counts = Counter(new_errors)
    
    old_counts = {}
    if os.path.exists(csv_path):
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                code = row.get("Error_Code")
                count = row.get("Original_Count") or row.get("Count", 0)
                if code and code != "None":
                    old_counts[code] = int(count)
                    
    all_codes = set(old_counts.keys()).union(set(new_counts.keys()))
    
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Error_Code", "Original_Count", "Current_Count"])
        
        if not all_codes:
            writer.writerow(["None", 0, 0])
        else:
            for code in sorted(all_codes):
                writer.writerow([code, old_counts.get(code, 0), new_counts.get(code, 0)])
                
    print(f"   📊 CSV atualizado: {len(new_errors)} erros de TypeScript identificados.")

def save_remaining_errors(repo_path, output_pre):
    """Agrupa os erros por ficheiro e salva na pasta remaining_errors."""
    logs_dir = f"{repo_path}_logs"
    out_dir = os.path.join(logs_dir, "remaining_errors")
    
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    
    file_errors = {}
    current_file = None
    
    for line in output_pre.splitlines():
        match = TS_FILE_ERROR_REGEX.match(line)
        if match:
            current_file = match.group(1).strip()
            if current_file not in file_errors:
                file_errors[current_file] = []
            file_errors[current_file].append(line)
        elif current_file and (line.startswith(" ") or line.startswith("\t")):
            file_errors[current_file].append(line)

    if not file_errors:
        return set()

    broken_files_set = set()
    for filepath, errors in file_errors.items():
        broken_files_set.add(filepath)
        safe_name = filepath.replace('/', '_').replace('\\', '_') + '.txt'
        out_file = os.path.join(out_dir, safe_name)
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(errors) + "\n")
            
    print(f"   📁 {len(file_errors)} ficheiro(s) quebrado(s) mapeado(s) para cirurgia.")
    return broken_files_set

# ==========================================
# FASE 2: ROLLBACK CIRÚRGICO (SINTAXE)
# ==========================================
def parse_inference_log(log_filepath):
    """Extrai os pares Original vs LLM dos logs."""
    with open(log_filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    patches = []
    blocks = content.split('=========================')
    for block in blocks:
        if not block.strip(): continue
        
        orig_match = re.search(r'Given the following code:\n+(.*?)\n+(?:Does this code have|\*\*Instructions:\*\*)', block, re.DOTALL)
        new_match = re.search(r'Output:\n```\w*\n(.*?)\n```', block, re.DOTALL)
        
        if orig_match and new_match:
            orig_code = orig_match.group(1).strip()
            new_code = new_match.group(1).strip()
            if new_code and "No security issues found" not in new_code:
                patches.append({'original': orig_code, 'new': new_code})
    return patches

def perform_surgical_rollback(repo_path, baseline_path, broken_files):
    if not broken_files:
        return 0, 0
        
    functions_saved = 0
    functions_rejected = 0
    logs_dir = f"{repo_path}_logs"
    
    for rel_path in broken_files:
        clean_rel_path = rel_path.strip()
        source_file = os.path.abspath(os.path.join(baseline_path, clean_rel_path))
        target_file = os.path.abspath(os.path.join(repo_path, clean_rel_path))
        log_file = os.path.abspath(os.path.join(logs_dir, clean_rel_path + ".txt"))
        
        if not os.path.exists(source_file) or not os.path.exists(log_file):
            if os.path.exists(source_file): shutil.copy2(source_file, target_file)
            continue
            
        print(f"      💉 Operando: {clean_rel_path}")
        patches = parse_inference_log(log_file)
        
        shutil.copy2(source_file, target_file)
        
        for i, patch in enumerate(patches, 1):
            with open(target_file, 'r', encoding='utf-8') as f:
                current_content = f.read()
                
            if patch['original'] in current_content:
                new_content = current_content.replace(patch['original'], patch['new'])
                with open(target_file, 'w', encoding='utf-8') as f: f.write(new_content)
                    
                output_test, _ = run_build(repo_path)
                
                # A MÁGICA REPARADA: Procura por erros TS no output e verifica numericamente
                has_fatal_syntax = False
                for ts_match in TS_ALL_REGEX.findall(output_test):
                    if is_syntax_error(ts_match):
                        has_fatal_syntax = True
                        break
                
                if not has_fatal_syntax:
                    print(f"         ✔️ Patch {i}/{len(patches)} retido (Livre de Erros de Sintaxe).")
                    functions_saved += 1
                else:
                    print(f"         ❌ Patch {i}/{len(patches)} rejeitado (Erro Sintático). Revertendo.")
                    with open(target_file, 'w', encoding='utf-8') as f: f.write(current_content)
                    functions_rejected += 1

    return functions_saved, functions_rejected

# ==========================================
# FASE 3: AMORDAÇAMENTO SEMÂNTICO (@ts-ignore)
# ==========================================
def apply_ts_ignore(repo_path):
    output, _ = run_build(repo_path)
    matches = TS_FILE_ERROR_REGEX.findall(output)
    
    if not matches:
        return 0
        
    errors_by_file = {}
    for filepath, line_str, ts_code in matches:
        # A MÁGICA REPARADA: Avalia numericamente se NÃO é erro de sintaxe
        if not is_syntax_error(ts_code):
            clean_path = filepath.strip()
            line_idx = int(line_str) - 1
            if clean_path not in errors_by_file: errors_by_file[clean_path] = set()
            errors_by_file[clean_path].add(line_idx)
            
    total_injected = 0
    for rel_path, lines in errors_by_file.items():
        abs_path = os.path.abspath(os.path.join(repo_path, rel_path))
        if not os.path.exists(abs_path): continue
            
        with open(abs_path, 'r', encoding='utf-8') as f: file_lines = f.readlines()
            
        sorted_lines = sorted(list(lines), reverse=True)
        injected_in_file = 0
        
        for line_idx in sorted_lines:
            if line_idx < len(file_lines):
                if line_idx > 0 and "@ts-ignore" in file_lines[line_idx - 1]: continue
                
                target_line = file_lines[line_idx]
                indent = len(target_line) - len(target_line.lstrip())
                spaces = " " * indent
                file_lines.insert(line_idx, f"{spaces}// @ts-ignore - LLM Type Hallucination Suppression\n")
                injected_in_file += 1
                total_injected += 1
                
        if injected_in_file > 0:
            with open(abs_path, 'w', encoding='utf-8') as f: f.writelines(file_lines)
            print(f"      🤐 Injetados {injected_in_file} @ts-ignore(s) em {rel_path}")

    return total_injected

def get_target_repositories():
    repos = []
    for path in glob.glob(SEARCH_PATTERN):
        if os.path.isdir(path) and not path.endswith("_logs"): repos.append(path)
    return sorted(repos)

if __name__ == "__main__":
    repositories = get_target_repositories()
    
    if not repositories:
        print("❌ Nenhum repositório de tratamento encontrado.")
    else:
        print(f"🔬 INICIANDO PIPELINE UNIFICADO DE PREPARAÇÃO EM {len(repositories)} REPOSITÓRIOS\n")
        
        for repo in repositories:
            print(f"\n==============================================")
            print(f"⚙️  Alvo: {repo}")
            
            print("\n[FASE 1] Mapeamento e Extração de Métricas (CSV)")
            output_initial, _ = run_build(repo)
            update_error_csv(repo, output_initial)
            broken_files = save_remaining_errors(repo, output_initial)
            
            if broken_files:
                print("\n[FASE 2] Rollback Cirúrgico (Rejeitando apenas Erros de Sintaxe)")
                saved, rejected = perform_surgical_rollback(repo, BASELINE_REPO, broken_files)
                print(f"   🛡️  Funções retidas: {saved} | 🗑️  Funções descartadas: {rejected}")
                
                print("\n[FASE 3] Amordaçamento Semântico (@ts-ignore)")
                ignores = apply_ts_ignore(repo)
                print(f"   ✅ Processo finalizado com {ignores} supressões.")
            else:
                print("   ✅ O repositório já está verde (0 erros). Saltando Fases 2 e 3.")

        print("\n" + "="*60)
        print("🎉 PIPELINE CONCLUÍDO COM SUCESSO! Todos os repositórios prontos para SAST/DAST.")
        print("="*60)