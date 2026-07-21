import os
from attacks.rule_engine import load_rules, generate_rule_pipeline


def merge_wordlists(paths, output_path):
    seen = set()
    count = 0
    with open(output_path, "w", encoding="utf-8") as out:
        for path in paths:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word and word not in seen:
                        seen.add(word)
                        out.write(word + "\n")
                        count += 1
    return count


def dedupe_wordlist(input_path, output_path):
    seen = set()
    count = 0
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        with open(output_path, "w", encoding="utf-8") as out:
            for line in f:
                word = line.strip()
                if word and word not in seen:
                    seen.add(word)
                    out.write(word + "\n")
                    count += 1
    return count


def apply_rules_to_wordlist(input_path, rules_path, output_path):
    rules = load_rules(rules_path)
    count = 0
    seen = set()
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f_in:
        with open(output_path, "w", encoding="utf-8") as f_out:
            for line in f_in:
                word = line.strip()
                if not word:
                    continue
                for variant in generate_rule_pipeline(word, rules):
                    if variant and variant not in seen:
                        seen.add(variant)
                        f_out.write(variant + "\n")
                        count += 1
    return count


def wordlist_stats(path):
    if not os.path.exists(path):
        return {"words": 0, "min_len": 0, "max_len": 0, "avg_len": 0}
    lengths = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w:
                lengths.append(len(w))
    if not lengths:
        return {"words": 0, "min_len": 0, "max_len": 0, "avg_len": 0}
    return {
        "words": len(lengths),
        "min_len": min(lengths),
        "max_len": max(lengths),
        "avg_len": sum(lengths) / len(lengths),
    }
