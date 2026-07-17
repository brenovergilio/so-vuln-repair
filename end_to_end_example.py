import os
import sys
import json
import subprocess
import time

sys.path.insert(0, os.path.abspath("."))

from utils import (
    get_ts_tree_sitter_language_and_parser,
    extract_functions,
    sanitize_code_semantics,
    get_func_id,
    get_type_aware_context,
    get_llama_tokenizer,
    count_llama_tokens,
)
from importlib import import_module

# importa o modulo de geracao para reusar os prompts reais
gen = import_module("3_6_generate_corrections")

TARGET_FILE = "routes/fileUpload.ts"
TARGET_FUNC = "handleZipFileUpload"
BASE_REPO = "./juice-shop"

CONTEXT_FILES = {
    "SOSecure":             "raw_so_contexts.json",
    "Extractive POSecure":  "compressed_contexts.json",
    "Abstractive POSecure": "abstractive_contexts.json",
    "CVEfixes":             "cvefixes_contexts.json",
}

SEP = "=" * 78

def banner(title):
    print("\n" + SEP)
    print(title)
    print(SEP)

def main():
    lang, parser = get_ts_tree_sitter_language_and_parser()
    tokenizer = get_llama_tokenizer()

    full_path = os.path.join(BASE_REPO, TARGET_FILE)
    if not os.path.exists(full_path):
        print("ERRO: nao encontrado:", full_path)
        return

    with open(full_path, "rb") as f:
        code_bytes = f.read()

    # 1. extrai as funcoes e localiza a alvo
    funcs = extract_functions(code_bytes, lang, parser)
    target = None
    for start, end, size, name in funcs:
        if name == TARGET_FUNC:
            target = (start, end, name)
            break

    if not target:
        print("Funcao nao encontrada. Funcoes disponiveis em", TARGET_FILE, ":")
        for _, _, _, n in funcs:
            if n:
                print("   -", n)
        return

    start, end, name = target
    original_func = code_bytes[start:end].decode("utf-8")

    banner("[1] ORIGINAL FUNCTION (as found in the repository)")
    print(original_func)

    # 2. sanitiza (filtro anti-leakage: remove comments e chamadas *challenge*)
    clean_func = sanitize_code_semantics(original_func, lang, parser)

    banner("[2] SANITIZED FUNCTION (anti-leakage filter applied; this is what the model sees)")
    print(clean_func)

    func_id = get_func_id(clean_func)
    print("\n   func_id (MD5):", func_id)
    print("   original tokens:", count_llama_tokens(original_func, tokenizer))
    print("   sanitized tokens:", count_llama_tokens(clean_func, tokenizer))

    # 3. type-aware context (1-hop). exige o server node rodando
    banner("[3] 1-HOP TYPE-AWARE CONTEXT (from the TypeScript Compiler API)")
    try:
        gen.cleanup_node_server()
        gen.start_type_extractor_server()
        time.sleep(2)
        type_sigs = get_type_aware_context(os.path.abspath(full_path), clean_func)
    except SystemExit as e:
        print("Falha ao contactar o type-extractor:", e)
        type_sigs = ""
    except Exception as e:
        print("Erro ao iniciar o servidor:", e)
        type_sigs = ""

    print(type_sigs if type_sigs else "(empty)")
    print("   type-context tokens:", count_llama_tokens(type_sigs, tokenizer))

    # 4. contextos recuperados por tecnica
    contexts = {}
    banner("[4] RETRIEVED CONTEXT PER TECHNIQUE")
    for label, path in CONTEXT_FILES.items():
        if not os.path.exists(path):
            print("\n--- %s: arquivo nao encontrado (%s)" % (label, path))
            contexts[label] = None
            continue
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ctx = data.get(TARGET_FILE, {}).get(func_id)
        contexts[label] = ctx
        print("\n" + "-" * 78)
        print("--- %s  (%s)" % (label, path))
        print("-" * 78)
        if ctx is None:
            print("(no context retrieved for this function)")
        else:
            print("tokens:", count_llama_tokens(ctx, tokenizer))
            print()
            print(ctx)

    # 5. prompts finais (um por tratamento)
    banner("[5] FINAL PROMPTS SENT TO THE MODEL")

    prompts = {}
    prompts["No RAG"] = gen.get_prompt_raw(clean_func, type_sigs)
    if contexts.get("SOSecure") is not None:
        prompts["SOSecure"] = gen.get_prompt_rag(clean_func, contexts["SOSecure"], type_sigs)
    if contexts.get("Extractive POSecure") is not None:
        prompts["Extractive POSecure"] = gen.get_prompt_posecure(clean_func, contexts["Extractive POSecure"], type_sigs)
    if contexts.get("Abstractive POSecure") is not None:
        prompts["Abstractive POSecure"] = gen.get_prompt_posecure(clean_func, contexts["Abstractive POSecure"], type_sigs)
    if contexts.get("CVEfixes") is not None:
        prompts["CVEfixes"] = gen.get_prompt_cvefixes(clean_func, contexts["CVEfixes"], type_sigs)

    for label, p in prompts.items():
        print("\n" + "-" * 78)
        print("--- PROMPT: %s   (%d tokens)" % (label, count_llama_tokens(p, tokenizer)))
        print("-" * 78)
        print(p)

    # 6. resumo comparativo de tokens
    banner("[6] TOKEN SUMMARY (illustrates the effect of compression)")
    print("%-24s %10s %10s" % ("technique", "ctx_tok", "prompt_tok"))
    print("-" * 46)
    print("%-24s %10s %10d" % ("No RAG", "-", count_llama_tokens(prompts["No RAG"], tokenizer)))
    for label in ["SOSecure", "Extractive POSecure", "Abstractive POSecure", "CVEfixes"]:
        if label in prompts:
            ct = count_llama_tokens(contexts[label], tokenizer)
            pt = count_llama_tokens(prompts[label], tokenizer)
            print("%-24s %10d %10d" % (label, ct, pt))

    try:
        gen.cleanup_node_server()
    except Exception:
        pass

if __name__ == "__main__":
    main()