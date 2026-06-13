import matplotlib.pyplot as plt

fig, ax = plt.subplots(figsize=(6, 2))
ax.axis('off')
ax.text(0.5, 0.5, 'HCLTech', color='#004A8F', fontsize=50, fontweight='bold', ha='center', va='center', fontfamily='sans-serif')
plt.savefig('images/hcltech_logo.png', dpi=300, transparent=True, bbox_inches='tight')
plt.close()
