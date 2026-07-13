import os
import re

html_files = [f for f in os.listdir('.') if f.endswith('.html')]

# Deep dark background & colors
replacements = {
    # CSS background and color
    'background: #0f172a;': 'background: #121212;',
    'color: #e2e8f0;': 'color: #f3f4f6;',
    
    # Nav and UI background adjustments
    'rgba(15,23,42,0.7)': 'rgba(20,20,20,0.8)',
    'rgba(15,23,42,0.95)': 'rgba(20,20,20,0.95)',
    'rgba(30,41,59,0.6)': 'rgba(30,30,30,0.6)',
    'rgba(30,41,59,0.5)': 'rgba(30,30,30,0.5)',
    'rgba(30,41,59,0.8)': 'rgba(34,34,34,0.8)',
    'rgba(30,41,59,0.4)': 'rgba(34,34,34,0.4)',
    'rgba(15,23,42,0.4)': 'rgba(30,30,30,0.5)',
    'rgba(15,23,42,0.5)': 'rgba(30,30,30,0.6)',
    'rgba(15,23,42,0.6)': 'rgba(30,30,30,0.7)',
    'rgba(15,23,42,0.9)': 'rgba(20,20,20,0.9)',
    '#1e293b': '#1e1e1e', # options in select
    
    # Border adjustments for darker theme
    'rgba(71,85,105,0.3)': 'rgba(80,80,80,0.4)',
    'rgba(71,85,105,0.4)': 'rgba(80,80,80,0.5)',
    'rgba(71,85,105,0.2)': 'rgba(80,80,80,0.3)',
    'rgba(71,85,105,0.15)': 'rgba(80,80,80,0.2)',
    'rgba(71,85,105,0.5)': 'rgba(80,80,80,0.6)',
    
    # Status Indicators replaced with Neon Accents
    # Emerald Green (Aligned / Fully Implemented)
    '#34d399': '#00ff88',
    'rgba(52,211,153,': 'rgba(0,255,136,',
    
    # Electric Yellow (Partial / Partially Implemented)
    '#fbbf24': '#ffea00',
    'rgba(251,191,36,': 'rgba(255,234,0,',

    # Neon Coral/Red (Gap / Not Implemented / Non-existent)
    '#ef4444': '#ff3366',
    'rgba(239,68,68,': 'rgba(255,51,102,',
    
    # Additional mappings for statuses in javascript maturityColors
    "'#ef4444','#f97316','#fbbf24','#38bdf8','#34d399','#818cf8'": "'#ff3366','#f97316','#ffea00','#38bdf8','#00ff88','#818cf8'",
}

for file_name in html_files:
    with open(file_name, 'r', encoding='utf-8') as f:
        content = f.read()
        
    for k, v in replacements.items():
        content = content.replace(k, v)
        
    # Typography: Clean monospaced fonts for control IDs.
    # In assessment.html:
    # `const ctrlClean = ctrl.replace(/^\d+\.\d+\s+/, '');`
    # Replace with logic that formats the ID.
    if file_name == 'assessment.html':
        replacement = r"""let ctrlId = '';
                    let ctrlName = ctrl;
                    const match = ctrl.match(/^(\d+(\.\d+)*)\s+(.*)/);
                    if (match) {
                        ctrlId = `<span style="font-family:'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; color: #818cf8; background: rgba(129,140,248,0.15); padding: 0.15rem 0.4rem; border-radius: 4px; border: 1px solid rgba(129,140,248,0.3); margin-right: 0.5rem; font-size: 0.85em; font-weight: 600;">ISO ${match[1]}</span>`;
                        ctrlName = match[3];
                    }
                    const ctrlClean = ctrlId + (ctrlId ? " " : "") + ctrlName;"""
        content = content.replace(
            r"const ctrlClean = ctrl.replace(/^\d+\.\d+\s+/, '');",
            replacement
        )
        
    # In mapping.html, we might want to do the same for the ISO controls listed:
    # We can check mapping.html if it has similar replacement logic.
    
    # In results.html or gaps.html there's logic that renders recommendations:
    # `[NCF IR-4]` or `[ISO 16.1.2]` inside strong or span blocks:
    if file_name == 'index.html':
        content = re.sub(
            r"\[ISO ([\d\.]+)\]",
            r"<span style=\"font-family:'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; color: #818cf8; background: rgba(129,140,248,0.15); padding: 0.15rem 0.4rem; border-radius: 4px; border: 1px solid rgba(129,140,248,0.3); font-size: 0.85em; font-weight: 600;\">ISO \1</span>",
            content
        )
        content = re.sub(
            r"\[NCF ([A-Z-]+)\]",
            r"<span style=\"font-family:'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; color: #38bdf8; background: rgba(56,189,248,0.15); padding: 0.15rem 0.4rem; border-radius: 4px; border: 1px solid rgba(56,189,248,0.3); font-size: 0.85em; font-weight: 600;\">NCF \1</span>",
            content
        )

    with open(file_name, 'w', encoding='utf-8') as f:
        f.write(content)

print('Updated theme globally!')
