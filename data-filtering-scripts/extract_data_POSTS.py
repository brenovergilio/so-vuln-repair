import subprocess
import xml.etree.ElementTree as ET
import json
import sys

# --- Configuration ---
source_file = "data-filtering-scripts/stackoverflow.com.7z"
output_file = "data-filtering-scripts/so_security_posts.jsonl"
target_inner_file = "Posts.xml"

# 1. What we want (Whitelist)
TARGET_TAGS = {
    "javascript", "typescript", "node.js", "angular", "angularjs", "reactjs", "vue.js",
    "express", "mean-stack", "sequelize", "typeorm", "nestjs", "electron", "ecmascript"
}

# 2.What we don't want (Blacklist)
EXCLUDE_TAGS = {
    "java", "c#", "php", "python", ".net", "c++", "ruby", "go", "android", "ios", 
    "swift", "r", "c", "asp.net", "laravel", "django", "spring", "flask"
}

print(f"--- STARTING PROCESSING (STRICT JS/TS FILTER) ---")
print(f"Targets: {len(TARGET_TAGS)} tags | Excludes: {len(EXCLUDE_TAGS)} tags")

cmd = ["7z", "e", "-so", source_file, target_inner_file]

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if process.stdout is None:
    raise RuntimeError("Error opening 7zip's pipe")

valid_question_ids = set()

try:
    context = ET.iterparse(process.stdout, events=("end",))
    count = 0
    saved = 0
    
    with open(output_file, "w", encoding="utf-8") as out_f:
        for event, elem in context:
            if elem.tag == "row":
                try:
                    id_str = elem.get("Id")
                    
                    if not id_str:
                        elem.clear()
                        continue
                        
                    post_id = int(id_str)
                    post_type = elem.get("PostTypeId")
                    
                    # --- Type 1: Question ---
                    if post_type == "1":
                        tags_raw = elem.get("Tags", "").lower()
                        if '<' in tags_raw:
                            tags_set = set(tags_raw.replace('<', ' ').replace('>', ' ').split())
                        else:
                            tags_set = set(tags_raw.split())
                        
                        if (tags_set & TARGET_TAGS) and not (tags_set & EXCLUDE_TAGS):
                            valid_question_ids.add(post_id)
                            
                            #data = {
                            #    "id": str(post_id),
                            #    "type": "1",
                            #    "parent_id": None,
                            #    "score": elem.get('Score'),
                            #    "tags": list(tags_set),
                            #    "title": elem.get("Title", ""),
                            #    "body": elem.get("Body", "")
                           #}
                            #out_f.write(json.dumps(data) + '\n')
                            #saved += 1

                    # --- Type 2: Answer ---
                    elif post_type == "2":
                        parent_id_str = elem.get("ParentId")

                        if parent_id_str:
                            parent_id = int(parent_id_str)
                            # Use just answers that parent's have passed TAGS filter
                            if parent_id in valid_question_ids:
                                data = {
                                    "id": str(post_id),
                                    "type": "2",
                                    "parent_id": str(parent_id),
                                    "score": elem.get('Score'),
                                    "body": elem.get("Body", "")
                                }
                                out_f.write(json.dumps(data) + '\n')
                                saved += 1
                            
                except Exception:
                    pass
    
                elem.clear()
                count += 1
                if count % 1000000 == 0:
                    print(f"Scanned: {count/1000000:.1f}M posts | Saved (Strict JS/TS): {saved}")
                    sys.stdout.flush()
                    
    process.stdout.close()
    process.wait()
    
    print(f"Success! Total Analyzed: {count}. Total Saved: {saved}.")

except KeyboardInterrupt:
    print("\nProcess interrupted by the user")
    process.kill()
