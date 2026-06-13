import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace figure(rect..., caption: [...]) with figure(..., caption: [...], kind: image)
# We can just look for caption: [some text], and if it's followed by ) <fig-, we insert kind: image if missing.
# Let's do a regex replacement.

pattern = re.compile(r'(caption:\s*\[.*?\]),\s*\)(\s*<fig-[a-zA-Z0-9-]+>)', re.DOTALL)
content = pattern.sub(r'\1,\n  kind: image,\n)\2', content)

# Check if any have been replaced
with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)
