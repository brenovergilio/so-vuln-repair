import os
import re

RESULTS_DIRS = [
    "./experiment_results/local/juice-shop",
    "./experiment_results/oci/juice-shop"
]

def relax_tsconfig(file_path):
    if not os.path.exists(file_path):
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 1. Remove qualquer menção prévia às flags que queremos forçar
        # Isso evita o problema de "Last Key Wins" do JSON
        content = re.sub(r'"noEmitOnError"\s*:\s*(true|false)\s*,?', '', content)
        content = re.sub(r'"strict"\s*:\s*(true|false)\s*,?', '', content)
        content = re.sub(r'"skipLibCheck"\s*:\s*(true|false)\s*,?', '', content)
        
        # 2. Injeta as nossas flags logo no início do bloco
        if '"compilerOptions": {' in content:
            injected_flags = '"compilerOptions": {\n    "noEmitOnError": false,\n    "strict": false,\n    "skipLibCheck": true,'
            content = content.replace('"compilerOptions": {', injected_flags, 1)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"   ✅ Relaxado com sucesso: {file_path}")
        else:
            print(f"   ⚠️ Bloco compilerOptions não encontrado em: {file_path}")
            
    except Exception as e:
        print(f"   ❌ Erro ao processar {file_path}: {e}")

def main():
    print("="*60)
    print("🔓 RELAXANDO REGRAS DO TYPESCRIPT (NO-EMIT-ON-ERROR)")
    print("="*60)
    
    target_dirs = []
    for base in RESULTS_DIRS:
        if os.path.exists(base):
            for d in os.listdir(base):
                full_path = os.path.join(base, d)
                if os.path.isdir(full_path) and d != "reports" and "logs" not in d:
                    target_dirs.append(full_path)
                    
    for target in target_dirs:
        print(f"\n📂 Processando: {os.path.basename(target)}")
        
        # 1. TSConfig do Backend (Raiz)
        backend_ts = os.path.join(target, "tsconfig.json")
        relax_tsconfig(backend_ts)
        
        # 2. TSConfig do Frontend (Mirando no app construtor correto)
        frontend_ts = os.path.join(target, "frontend", "tsconfig.base.json")
        relax_tsconfig(frontend_ts)

if __name__ == "__main__":
    main()