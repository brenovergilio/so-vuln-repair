import json
import os

# --- Configuration ---
# Substitua pelo nome do arquivo gerado no seu último passo
input_file = "sosecure_js_ts_final.jsonl" 

def count_database_stats(filepath):
    if not os.path.exists(filepath):
        print(f"❌ Error: File '{filepath}' not found.")
        return

    total_answers = 0
    total_comments = 0

    print(f"📊 Analyzing '{filepath}'...")

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                doc = json.loads(line)
                
                # Cada linha válida no JSONL é uma Resposta (Answer) do Stack Overflow
                total_answers += 1
                
                # Conta quantos comentários estão atrelados a essa resposta
                comments_list = doc.get("comments", [])
                total_comments += len(comments_list)
                
            except json.JSONDecodeError:
                print(f"⚠️ Warning: Could not parse JSON on line {line_num}")
                continue

    print("=" * 40)
    print("📈 FINAL DATABASE STATISTICS")
    print("=" * 40)
    print(f"Total Answers (Posts) : {total_answers:,}")
    print(f"Total Comments        : {total_comments:,}")
    print("=" * 40)

if __name__ == "__main__":
    count_database_stats(input_file)