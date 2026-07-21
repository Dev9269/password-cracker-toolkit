import json
import csv
import os


def _csv_rows_from_data(data):
    rows = []
    if isinstance(data, list):
        for entry in data:
            r = entry.get("result", {})
            rows.append(
                [
                    entry.get("hash", ""),
                    r.get("hash_type", ""),
                    "Cracked" if r.get("success") else "Failed",
                    r.get("password", ""),
                    f"{r.get('time_elapsed', 0):.4f}",
                    r.get("attempts", 0),
                    f"{r.get('attempts_per_second', 0):.1f}",
                ]
            )
    elif "results" in data:
        for entry in data["results"]:
            r = entry.get("result", {})
            rows.append(
                [
                    entry.get("hash", ""),
                    r.get("hash_type", ""),
                    "Cracked" if r.get("success") else "Failed",
                    r.get("password", ""),
                    f"{r.get('time_elapsed', 0):.4f}",
                    r.get("attempts", 0),
                    f"{r.get('attempts_per_second', 0):.1f}",
                ]
            )
    else:
        rows.append(
            [
                data.get("hash", ""),
                data.get("hash_type", ""),
                "Cracked" if data.get("success") else "Failed",
                data.get("password", ""),
                f"{data.get('time_elapsed', 0):.4f}",
                data.get("attempts", 0),
                f"{data.get('attempts_per_second', 0):.1f}",
            ]
        )
    return rows


def write_report(results, output_path, fmt="json"):
    dirname = os.path.dirname(output_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname)
    if fmt == "json":
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
    elif fmt == "csv":
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Hash",
                    "Algorithm",
                    "Status",
                    "Password",
                    "Time (s)",
                    "Attempts",
                    "Speed (s)",
                ]
            )
            writer.writerows(_csv_rows_from_data(results))


def append_to_report(result_entry, output_path):
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            data = {"results": []}
    else:
        data = {"results": []}
    data.setdefault("results", []).append(result_entry)
    write_report(data, output_path, "json")
