import matplotlib.pyplot as plt
import textwrap
import os

def render_markdown_table_to_png(md_filepath, png_filepath):
    with open(md_filepath, 'r') as f:
        lines = f.readlines()

    table_data = []
    for line in lines:
        line = line.strip()
        if line.startswith('|'):
            if '---' in line:  # Ayırıcı satırı atla
                continue
            # Markdown kalıntılarını ve bold taglerini temizle, veriyi al
            cells = [cell.strip().replace('**', '') for cell in line.split('|')[1:-1]]
            table_data.append(cells)

    if not table_data:
        print("Tablo verisi bulunamadı.")
        return

    headers = table_data[0]
    data = table_data[1:]

    # Hücre içindeki uzun metinleri satırlara böl (# of chars per line wrap)
    wrap_widths = [10, 30, 25, 40, 35] 
    wrapped_data = []
    for row in data:
        wrapped_row = []
        for i, cell in enumerate(row):
            width = wrap_widths[i] if i < len(wrap_widths) else 30
            wrapped_row.append(textwrap.fill(cell, width=width))
        wrapped_data.append(wrapped_row)

    # Figür oluştur (Satır sayısına göre yüksekliği ayarla)
    fig_height = len(data) * 0.8 + 1
    fig, ax = plt.subplots(figsize=(15, fig_height))
    ax.axis('tight')
    ax.axis('off')

    # Tabloyu çiz
    table = ax.table(
        cellText=wrapped_data, 
        colLabels=headers, 
        loc='center', 
        cellLoc='left',
        colWidths=[0.06, 0.2, 0.2, 0.3, 0.24]
    )

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 4)

    # Başlık satırının tasarımını kalın ve farklı renk yap
    for j, _ in enumerate(headers):
        cell = table[0, j]
        cell.set_text_props(weight='bold', color='white')
        cell.set_facecolor('#2c3e50')
        cell.set_edgecolor('#bdc3c7')

    # Satır alternatif renklendirmesi
    for i in range(1, len(data) + 1):
        for j in range(len(headers)):
            cell = table[i, j]
            cell.set_edgecolor('#bdc3c7')
            if i % 2 == 0:
                cell.set_facecolor('#f9f9f9')

    plt.title('Validation of Experimental Scenarios against Literature Findings', fontweight='bold', fontsize=14, y=1.02)
    plt.tight_layout()
    plt.savefig(png_filepath, dpi=300, bbox_inches='tight')
    print(f"Başarıyla tablo görseli oluşturuldu: {png_filepath}")

if __name__ == '__main__':
    render_markdown_table_to_png('paper_comparison_table.md', 'paper_comparison_table.png')
