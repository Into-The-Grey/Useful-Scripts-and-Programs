import yaml
import csv
import argparse

def main():
    parser = argparse.ArgumentParser(description="Convert a YAML list of records to CSV or TSV.")
    parser.add_argument("input", help="Path to the input YAML file")
    parser.add_argument("output", help="Path to the output CSV/TSV file")
    parser.add_argument("--tsv", action="store_true", help="Output TSV instead of CSV")
    args = parser.parse_args()

    # Load YAML data
    with open(args.input, 'r') as infile:
        data = yaml.safe_load(infile)

    # Define columns based on expected keys
    fields = [
        "author", "dependencies", "description",
        "files", "last_updated", "name",
        "path", "required_keys", "version"
    ]

    # Choose delimiter
    delimiter = "\t" if args.tsv else ","

    # Write to CSV/TSV
    with open(args.output, 'w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fields, delimiter=delimiter)
        writer.writeheader()
        for record in data:
            # Flatten list fields by joining with semicolon
            row = {}
            for key in fields:
                value = record.get(key, "")
                if isinstance(value, list):
                    row[key] = ";".join(str(v) for v in value)
                else:
                    row[key] = str(value)
            writer.writerow(row)

if __name__ == "__main__":
    main()

# Usage:
#   python yaml_to_csv.py modules.yaml modules.csv
#   python yaml_to_csv.py modules.yaml modules.tsv --tsv
