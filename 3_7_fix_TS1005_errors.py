import os
import subprocess
import re
import glob
import csv
from collections import Counter

# --- CONFIGURAÇÕES ---
# Padrão de busca dinâmico: encontra tudo dentro de experiment_results/<qualquer-provider>/juice-shop/<qualquer-tratamento>
SEARCH_PATTERN = "./experiment_results/*/juice-shop/*"

# Comando que dispara o compilador TypeScript no Juice Shop
BUILD_COMMAND = ["npm", "run", "build:server"]

# Regex para capturar os erros a serem consertados
TS1005_REGEX = re.compile(r"(.+?)\((\d+),(\d+)\): error TS1005: '(.+?)' expected\.")

def get_target_repositories():
    """Busca todas as pastas de tratamento validas, ignorando as de logs."""
    repos = []
    # glob.glob expande o asterisco para encontrar os caminhos reais
    for path in glob.glob(SEARCH_PATTERN):
        # Garante que é uma pasta e que o nome não termina com "_logs"
        if os.path.isdir(path) and not path.endswith("_logs"):
            repos.append(path)
            
    # Ordena alfabeticamente para a execução ficar organizada no terminal
    return sorted(repos)

def run_tsc_and_fix(repo_path, max_iterations=10):
    print(f"\n🚀 Iniciando Auto-Healer no repositório: {repo_path}")
    
    # Define o caminho da pasta de logs baseada no caminho do repositório
    logs_dir = f"{repo_path}_logs"
    os.makedirs(logs_dir, exist_ok=True)  # Garante que a pasta de logs existe
    csv_log_path = os.path.join(logs_dir, "tsc_errors.csv")
    
    for iteration in range(1, max_iterations + 1):
        print(f"   🔄 Iteração {iteration}... ", end="", flush=True)
        
        process = subprocess.run(
            BUILD_COMMAND, 
            cwd=repo_path, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True
        )
        
        output = process.stdout
        
        # --- MÁGICA DOS LOGS: Captura o estado original na Iteração 1 ---
        if iteration == 1:
            # Encontra todas as ocorrências do erro TS1005 na saída
            ts_1005_matches = TS1005_REGEX.findall(output)
            
            # Salva no CSV
            with open(csv_log_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Error_Code", "Count"])
                
                if not ts_1005_matches:
                    writer.writerow(["None", 0])
                else:
                    # Como só buscamos TS1005, gravamos diretamente o total
                    writer.writerow(["TS1005", len(ts_1005_matches)])
                    
            print(f"   📊 Log de erros originais salvo em {csv_log_path}")
        # ---------------------------------------------------------------
        
        if process.returncode == 0:
            print("   ✅ Compilação limpa! AST íntegro.")
            break
            
        matches = TS1005_REGEX.findall(output)
        
        if not matches:
            print(f"Erro: {output}") # Descomente se quiser ver a saída completa quando falhar
            print("   ⚠️ Falha na compilação, mas nenhum erro 'TS1005' encontrado. Parando o loop.")
            break
            
        print(f"   🔨 Encontrados {len(matches)} erros TS1005. Aplicando injeção...")
        
        errors_by_file = {}
        for match in matches:
            filepath, line_str, col_str, expected_char = match
            abs_filepath = os.path.abspath(os.path.join(repo_path, filepath.strip()))
            
            if abs_filepath not in errors_by_file:
                errors_by_file[abs_filepath] = []
            
            errors_by_file[abs_filepath].append({
                'line': int(line_str),
                'col': int(col_str),
                'char': expected_char
            })
            
        for filepath, errors in errors_by_file.items():
            if not os.path.exists(filepath):
                print(f"      ❌ Arquivo não encontrado: {filepath}")
                continue
                
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            # MÁGICA: Ordena de baixo para cima (descendente) por linha e coluna.
            errors.sort(key=lambda x: (x['line'], x['col']), reverse=True)
            
            for err in errors:
                line_idx = err['line'] - 1
                col_idx = err['col'] - 1
                char = err['char']
                
                while len(lines) <= line_idx:
                    lines.append("\n")
                    
                target_line = lines[line_idx]
                lines[line_idx] = target_line[:col_idx] + char + target_line[col_idx:]
                
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
    else:
        print("   ⚠️ Limite máximo de iterações atingido (possível loop infinito).")

if __name__ == "__main__":
    repositories = get_target_repositories()
    
    if not repositories:
        print("❌ Nenhum repositório de tratamento encontrado com o padrão fornecido.")
    else:
        print(f"🔍 Foram encontrados {len(repositories)} repositórios para processar.")
        for repo in repositories:
            run_tsc_and_fix(repo)