import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all blocks that are #figure(...) with kind: image
# and extract the caption and the image path/filename.
# A figure could be either image() or rect(...)
pattern = re.compile(r'#figure\((.*?)\)\s*<.*?>', re.DOTALL)
figures = pattern.findall(content)

count = 1
for fig in figures:
    if 'kind: image' in fig:
        # Extract caption
        caption_match = re.search(r'caption:\s*\[(.*?)\]', fig, re.DOTALL)
        caption = caption_match.group(1).strip() if caption_match else "No caption"
        
        # Determine if it's an image we generated or a manual screenshot rect
        if 'image(' in fig:
            img_match = re.search(r'image\("images/(.*?)"', fig)
            filename = img_match.group(1) if img_match else "unknown"
            print(f"Figure {count}: {filename} (GENERATED)")
        elif 'rect(' in fig:
            file_match = re.search(r'File: eport/images/(.*?)', fig)
            filename = file_match.group(1) if file_match else "unknown"
            print(f"Figure {count}: {filename} (MANUAL)")
        count += 1
