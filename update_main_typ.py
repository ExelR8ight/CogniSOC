import re
import sys

with open('report/main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

def replace_placeholder(match):
    text = match.group(0)
    file_match = re.search(r'File:\s*`(report/images/[^`]+)`', text)
    if not file_match:
        return text
    
    file_path = file_match.group(1).replace('report/images/', 'images/')
    
    if 'vscode_project_structure.png' in file_path:
        return '''grid(
    columns: 1,
    row-gutter: 10pt,
    image("images/vscode_project_structure_1.png", width: 40%),
    image("images/vscode_project_structure_2.png", width: 40%)
  ),'''
    elif 'dash_dashboard_full.png' in file_path:
        return '''grid(
    columns: 1,
    row-gutter: 10pt,
    image("images/dash_dashboard_full_1.png", width: 100%),
    image("images/dash_dashboard_full_2.png", width: 100%),
    image("images/dash_dashboard_full_3.png", width: 100%)
  ),'''
    elif 'splunk_soc_dashboard.png' in file_path:
        return '''grid(
    columns: 1,
    row-gutter: 10pt,
    image("images/splunk_soc_dashboard_1.png", width: 100%),
    image("images/splunk_soc_dashboard_2.png", width: 100%),
    image("images/splunk_soc_dashboard_3.png", width: 100%),
    image("images/splunk_soc_dashboard_4.png", width: 100%),
    image("images/splunk_soc_dashboard_5.png", width: 100%),
    image("images/splunk_soc_dashboard_6.png", width: 100%),
    image("images/splunk_soc_dashboard_7.png", width: 100%),
    image("images/splunk_soc_dashboard_8.png", width: 100%)
  ),'''
    else:
        return f'image("{file_path}", width: 100%),'

new_content = re.sub(r'rect\(width: 100%[^{<]*?File:\s*`report/images/[^`]+`[^\]]*?\]\s*\]\s*\],', replace_placeholder, content, flags=re.DOTALL)

with open('report/main.typ', 'w', encoding='utf-8') as f:
    f.write(new_content)
print('Done!')
