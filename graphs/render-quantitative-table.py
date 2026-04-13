import matplotlib.pyplot as plt
import textwrap

def render_quantitative_table_to_png(md_filepath, png_filepath):
    with open(md_filepath, 'r') as f:
        lines = f.readlines()

    table_data = []
    for line in lines:
        line = line.strip()
        if line.startswith('|'):
            if '---' in line:
                continue
            cells = [cell.strip().replace('**', '') for cell in line.split('|')[1:-1]]
            table_data.append(cells)

    if not table_data:
        return

    headers = table_data[0]
    data = table_data[1:]

    wrap_widths = [20, 35, 30, 30] 
    wrapped_data = []
    for row in data:
        wrapped_row = []
        for i, cell in enumerate(row):
            width = wrap_widths[i] if i < len(wrap_widths) else 30
            wrapped_row.append(textwrap.fill(cell, width=width))
        wrapped_data.append(wrapped_row)

    fig_height = len(data) * 0.9 + 1
    fig, ax = plt.subplots(figsize=(16, fig_height))
    ax.axis('tight')
    ax.axis('off')

    table = ax.table(
        cellText=wrapped_data, 
        colLabels=headers, 
        loc='center', 
        cellLoc='left',
        colWidths=[0.2, 0.3, 0.25, 0.25]
    )

    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1, 4)

    for j, _ in enumerate(headers):
        cell = table[0, j]
        cell.set_text_props(weight='bold', color='white')
        cell.set_facecolor('#2980b9')
        cell.set_edgecolor('#bdc3c7')

    for i in range(1, len(data) + 1):
        for j in range(len(headers)):
            cell = table[i, j]
            cell.set_edgecolor('#bdc3c7')
            if i % 2 == 0:
                cell.set_facecolor('#ecf0f1')

    plt.title('Quantitative Impact Analysis: Literature Findings vs. Experimental PoC', fontweight='bold', fontsize=15, y=1.02)
    plt.tight_layout()
    plt.savefig(png_filepath, dpi=300, bbox_inches='tight')
    print(f"Başarıyla tablo görseli oluşturuldu: {png_filepath}")

if __name__ == '__main__':
    render_quantitative_table_to_png('quantitative_comparison_table.md', 'quantitative_comparison_table.png')
