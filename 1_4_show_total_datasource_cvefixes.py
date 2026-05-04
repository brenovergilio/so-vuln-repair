import csv
import sys

csv.field_size_limit(sys.maxsize)
CSV_PATH = "ts_js_cvefixes.csv"

with open(CSV_PATH, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    next(reader)
    total = sum(1 for _ in reader)

print(f"Total de pares únicos (vulnerable → fixed): {total}")