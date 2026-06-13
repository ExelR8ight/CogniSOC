with open('main.typ', 'r', encoding='utf-8') as f:
    lines = f.readlines()

figure_num = 1
for i, line in enumerate(lines):
    if 'kind: image' in line:
        # look backward for caption or rect/image
        for j in range(i, max(-1, i-20), -1):
            if 'images/' in lines[j]:
                filename = lines[j].strip().split('images/')[-1].split('"')[0].split('')[0].split('.')[0]
                print(f"Figure {figure_num}: {filename}.png")
                break
        figure_num += 1
