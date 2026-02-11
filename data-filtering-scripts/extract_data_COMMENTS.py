import subprocess
import xml.etree.ElementTree as ET
import json
import sys

posts_file = "data-filtering-scripts/so_security_posts.jsonl"
comments_output_file = "data-filtering-scripts/so_security_comments.jsonl"
comments_archive = "data-filtering-scripts/stackoverflow.com.7z"
target_inner_file = "Comments.xml"

print(f"--- Mapping IDs retrieved from '{posts_file}' ---")
valid_post_ids = set()

try:
    with open(posts_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line)
                valid_post_ids.add(data['id']) 
            except json.JSONDecodeError:
                continue
    
    print(f"Mapped IDs on RAM: {len(valid_post_ids)}")

except FileNotFoundError:
    print("ERROR: Posts file not found.")
    sys.exit(1)

print(f"--- Extracting Comments from '{target_inner_file}' ---")

cmd = ["7z", "e", "-so", comments_archive, target_inner_file]
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if process.stdout is None:
    raise RuntimeError("Error opening 7zip pipe")

context = ET.iterparse(process.stdout, events=('end',))
count = 0
saved = 0

with open(comments_output_file, 'w', encoding='utf-8') as out_f:
    for event, elem in context:
        if elem.tag == 'row':
            try:
                post_id = elem.get('PostId')
                
                if post_id in valid_post_ids:
                    comment_data = {
                        "id": elem.get('Id'),
                        "post_id": post_id,
                        "text": elem.get('Text'),
                        "score": elem.get('Score'),
                        "creation_date": elem.get('CreationDate'),
                        "user_id": elem.get('UserId')
                    }
                    out_f.write(json.dumps(comment_data) + '\n')
                    saved += 1
            except Exception:
                pass
            
            elem.clear()
            count += 1
            if count % 1000000 == 0:
                print(f"Processed: {count/1000000:.1f}M | Saved: {saved}")
                sys.stdout.flush()

process.terminate()
print(f"Concluded! Comments saved in: {comments_output_file}")
print(f"Total of extracted Comments: {saved}")