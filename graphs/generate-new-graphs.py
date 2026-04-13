import json
import glob
import os
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = '../tests/results/'
GRAPHS_DIR = './'

def load_data():
    data = {}
    for file in glob.glob(os.path.join(RESULTS_DIR, '*.json')):
        with open(file, 'r') as f:
            name = os.path.basename(file).replace('.json', '')
            data[name] = json.load(f)
    return data

def plot_attack_success_rates(data):
    """NEW: Expanded to include T9 and T11"""
    features = ['Replay\n(T4)', 'alg:none\n(T4)', 'Redir URI\n(T5)', 'CSRF\n(T6)', 'Identity\n(T7)', 'Exp Manip\n(T9)', 'Role Esc\n(T11)']
    
    insecure = [
        data.get('t4_insecure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t4_insecure', {}).get('results', [{}, {}])[1].get('attackSuccessful', False) if len(data.get('t4_insecure', {}).get('results', [])) > 1 else False,
        data.get('t5_insecure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t6_insecure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t7_insecure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t9_insecure', {}).get('results', [{}, {}])[1].get('attackSuccessful', False) if len(data.get('t9_insecure', {}).get('results', [])) > 1 else False,
        data.get('t11_insecure', {}).get('results', [{}, {}])[1].get('attackSuccessful', False) if len(data.get('t11_insecure', {}).get('results', [])) > 1 else False,
    ]
    
    secure = [
        data.get('t4_secure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t4_secure', {}).get('results', [{}, {}])[1].get('attackSuccessful', False) if len(data.get('t4_secure', {}).get('results', [])) > 1 else False,
        data.get('t5_secure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t6_secure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t7_secure', {}).get('results', [{}])[0].get('attackSuccessful', False),
        data.get('t9_secure', {}).get('results', [{}, {}])[1].get('attackSuccessful', False) if len(data.get('t9_secure', {}).get('results', [])) > 1 else False,
        data.get('t11_secure', {}).get('results', [{}, {}])[1].get('attackSuccessful', False) if len(data.get('t11_secure', {}).get('results', [])) > 1 else False,
    ]

    insecure_pct = [100 if x else 0 for x in insecure]
    secure_pct = [100 if x else 0 for x in secure]
    
    x = np.arange(len(features))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(12, 6))
    bars1 = ax.bar(x - width/2, insecure_pct, width, label='Insecure Mode', color='#e74c3c', edgecolor='#c0392b')
    bars2 = ax.bar(x + width/2, secure_pct, width, label='Secure Mode (PKCE/RS256)', color='#2ecc71', edgecolor='#27ae60')
    
    # Add value labels
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 2, f'{int(h)}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 2, f'{int(h)}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax.set_ylabel('Attack Success Rate (%)', fontweight='bold', fontsize=12)
    ax.set_title('Fig. 1 — SSO Attack Vector Mitigation (Insecure vs Secure Mode)', fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(features, fontsize=10)
    ax.legend(fontsize=11)
    ax.set_ylim([0, 120])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, 'new_attack_mitigation_sso.png'), dpi=300)
    print("Generated: new_attack_mitigation_sso.png")

def plot_spof_comparison(data):
    """NEW: T8 with nuanced new/existing token data"""
    t8 = data.get('t8_insecure', {}).get('results', [{}])[0]
    new_login = t8.get('newLoginAvailability', 0)
    existing = t8.get('existingTokenAccess', 0)
    trad_survivors = data.get('t3_insecure', {}).get('results', [{}])[0].get('survivors', 3)

    labels = ['Traditional\n(1 crash)', 'SSO New Login\n(IdP down)', 'SSO Existing\nToken (IdP down)']
    values = [trad_survivors, new_login, existing]
    colors = ['#3498db', '#e74c3c', '#f39c12']

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors, width=0.5, edgecolor=['#2980b9', '#c0392b', '#e67e22'])
    
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.1, f'{val}/4', ha='center', va='bottom', fontsize=14, fontweight='bold')
    
    ax.set_ylabel('Available Services (out of 4)', fontweight='bold', fontsize=12)
    ax.set_title('Fig. 2 — SPOF Analysis: Service Availability Under Failure', fontweight='bold', fontsize=13)
    ax.set_ylim([0, 5])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, 'new_spof_comparison.png'), dpi=300)
    print("Generated: new_spof_comparison.png")

def plot_dos_bottleneck(data):
    """NEW: T10 DoS bottleneck comparison"""
    t10 = data.get('t10_insecure', {}).get('results', [])
    if len(t10) < 2:
        print("Skipping T10 graph — insufficient data")
        return
    
    trad = t10[0]
    sso = t10[1]
    
    metrics = ['Mean', 'p50', 'p95', 'p99', 'Max']
    trad_vals = [trad.get('meanMs', 0), trad.get('p50Ms', 0), trad.get('p95Ms', 0), trad.get('p99Ms', 0), trad.get('maxMs', 0)]
    sso_vals = [sso.get('meanMs', 0), sso.get('p50Ms', 0), sso.get('p95Ms', 0), sso.get('p99Ms', 0), sso.get('maxMs', 0)]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width/2, trad_vals, width, label='Traditional (4 Servers)', color='#3498db', edgecolor='#2980b9')
    bars2 = ax.bar(x + width/2, sso_vals, width, label='SSO (Single IdP)', color='#e74c3c', edgecolor='#c0392b')
    
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 10, f'{int(h)}ms', ha='center', va='bottom', fontsize=9, fontweight='bold')
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 10, f'{int(h)}ms', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax.set_ylabel('Response Time (ms)', fontweight='bold', fontsize=12)
    ax.set_title('Fig. 3 — DoS Bottleneck: 100 Concurrent Requests (Traditional vs SSO)', fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=11)
    ax.legend(fontsize=11)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, 'new_dos_bottleneck.png'), dpi=300)
    print("Generated: new_dos_bottleneck.png")

def plot_brute_force_stats(data):
    """NEW: T1 multi-run brute force with error bars"""
    t1 = data.get('t1_insecure', {}).get('results', [])
    if not t1:
        print("Skipping T1 graph — no data")
        return
    
    labels = [r.get('endpoint', '').split(':')[-1].split('/')[0] for r in t1]
    means = [r.get('avgTimeToCrackMs', 0) for r in t1]
    stddevs = [r.get('stddevMs', 0) for r in t1]
    
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, means, yerr=stddevs, capsize=8, color='#e67e22', edgecolor='#d35400', alpha=0.9)
    
    for bar, m, s in zip(bars, means, stddevs):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + s + 10, f'{m}±{s}ms', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_ylabel('Time to Crack (ms)', fontweight='bold', fontsize=12)
    ax.set_title('Fig. 4 — Brute Force: Mean Crack Time per Endpoint (n=5)', fontweight='bold', fontsize=13)
    ax.set_xlabel('Port', fontweight='bold', fontsize=12)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, 'new_brute_force_stats.png'), dpi=300)
    print("Generated: new_brute_force_stats.png")

def plot_attack_surface(data):
    """Same as before but with new_ prefix"""
    fig, ax = plt.subplots(figsize=(7, 5))
    labels = ['Traditional\n(4 endpoints)', 'SSO\n(1 IdP)']
    surface = [4, 1]
    ax.bar(labels, surface, color=['#95a5a6', '#2980b9'], width=0.5, edgecolor=['#7f8c8d', '#2471a3'])
    ax.set_ylabel('Number of Attack Vectors', fontweight='bold', fontsize=12)
    ax.set_title('Fig. 5 — Brute-Force Attack Surface Reduction', fontweight='bold', fontsize=13)
    ax.set_ylim([0, 5])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, 'new_attack_surface.png'), dpi=300)
    print("Generated: new_attack_surface.png")

if __name__ == "__main__":
    d = load_data()
    plot_attack_success_rates(d)
    plot_spof_comparison(d)
    plot_dos_bottleneck(d)
    plot_brute_force_stats(d)
    plot_attack_surface(d)
    print("\nAll NEW graphs generated successfully.")
