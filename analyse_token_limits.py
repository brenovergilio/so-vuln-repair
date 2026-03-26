import re
import sys
import os

def analyze_token_limits(file_path):
    # Check if the file exists before trying to open it
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)
        
    # Regex to capture the exact integer value preceding the word "tokens"
    pattern = re.compile(r"(\d+)\s*tokens")
    token_values = []
    
    try:
        # Read the file line by line to handle potentially large log files efficiently
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                matches = pattern.findall(line)
                for match in matches:
                    token_values.append(int(match))
    except Exception as e:
        print(f"Error reading the file: {e}")
        sys.exit(1)
        
    if not token_values:
        print("Error: No token values could be parsed from the provided file.")
        sys.exit(1)
        
    # Calculate min, max, average, and total count
    min_tokens = min(token_values)
    max_tokens = max(token_values)
    total_entries = len(token_values)
    avg_tokens = sum(token_values) / total_entries
    
    # Print the formatted report
    print("=== TOKEN ANALYSIS REPORT ===")
    print(f"File processed          : {file_path}")
    print(f"Total entries processed : {total_entries}")
    print(f"Minimum token count     : {min_tokens}")
    print(f"Maximum token count     : {max_tokens}")
    print(f"Average token count     : {avg_tokens:.2f}")
    print("=============================")
    
    return min_tokens, max_tokens

if __name__ == "__main__":
    # Hardcoded file path
    log_file_path = "token_analysis_report.txt"
    
    print(f"Analyzing '{log_file_path}'...")
    analyze_token_limits(log_file_path)