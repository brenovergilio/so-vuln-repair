import subprocess
import sys
import time
import os
from datetime import timedelta

SCRIPTS = [
    "./data-filtering-scripts/extract_data_POSTS.py",
    "./data-filtering-scripts/extract_data_COMMENTS.py",             
    "./data-filtering-scripts/generate_final_datasource.py",
]

def run_pipeline():
    total_start = time.time()
    cwd = os.getcwd()
    
    print("="*60)
    print(f"GETTING FINAL DATASOURCE FOR RAG - {len(SCRIPTS)} STEPS")
    print("="*60)

    for i, script_path in enumerate(SCRIPTS, 1):
        step_start = time.time()
        script_name = os.path.basename(script_path)
        print(f"\n>>> STEP {i}/{len(SCRIPTS)}: Executing {script_name}...")
        print("-" * 60)
        
        try:
            subprocess.run([sys.executable, script_path], check=True)
            
            elapsed = time.time() - step_start
            print("-" * 60)
            print(f"{script_name} CONCLUDED in {str(timedelta(seconds=int(elapsed)))}")
            
        except subprocess.CalledProcessError:
            print("!" * 60)
            print(f"CRITICAL ERROR in {script_name}.")
            print("!" * 60)
            sys.exit(1)
            
        except FileNotFoundError:
            print(f"FILE NOT FOUND: {script_name}")
            sys.exit(1)
            
        except KeyboardInterrupt:
            print("\nScript interrupted by the user.")
            sys.exit(0)

    total_elapsed = time.time() - total_start
    print("\n" + "="*60)
    print(f"🎉 FINISHED!")
    print(f"Time elapsed: {str(timedelta(seconds=int(total_elapsed)))}")
    print("="*60)

if __name__ == "__main__":
    run_pipeline()
