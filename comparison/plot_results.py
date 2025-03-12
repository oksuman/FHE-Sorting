import os
import re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import gridspec

script_dir = os.path.dirname(os.path.abspath(__file__))
results_dir = os.path.join(script_dir, "experimental_results")

data = {
    'algorithm': [],
    'k_value': [],
    'size': [],
    'time': []
}

algorithms = ['ours', 'ours_hybrid', 'mehp24', 'kway_k2', 'kway_k3', 'kway_k5']

for algo in algorithms:
    algo_dir = os.path.join(results_dir, algo)
    if not os.path.exists(algo_dir):
        print(f"Warning: Directory not found: {algo_dir}")
        continue
        
    for size_file in os.listdir(algo_dir):
        if size_file.startswith("N") and size_file.endswith("_summary.txt"):
            size = int(re.search(r'N(\d+)_summary', size_file).group(1))
            file_path = os.path.join(algo_dir, size_file)
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            time_match = re.search(r'Average Time\s*:\s*(\d+(?:\.\d+)?)', content)
            if time_match:
                time = float(time_match.group(1))  # Keep time in seconds
                
                k_value = None
                if 'kway_k' in algo:
                    k_value = int(algo.split('_k')[1])
                
                data['algorithm'].append(algo)
                data['k_value'].append(k_value)
                data['size'].append(size)
                data['time'].append(time)

df = pd.DataFrame(data)

if df.empty:
    print("No data was extracted. Cannot create plots.")
    exit()

print(f"Extracted data: {len(df)} rows")
print(df)

df_base = df[~df['algorithm'].str.contains('kway')].copy()
df_kway = df[df['algorithm'].str.contains('kway')].copy()

df['display_name'] = df['algorithm']
for i, row in df.iterrows():
    if 'kway_k' in row['algorithm']:
        df.at[i, 'display_name'] = f'kway (k={row["k_value"]})'

print("\nAlgorithms found in data:")
for algo in df['display_name'].unique():
    count = len(df[df['display_name'] == algo])
    print(f"Algorithm: {algo}, Data points: {count}")

min_time = df['time'].min()
max_time = df['time'].max()

algo_colors = {
    'ours': 'blue',
    'ours_hybrid': 'green',
    'mehp24': 'red',
    'kway (k=2)': 'purple',
    'kway (k=3)': 'orange',
    'kway (k=5)': 'brown'
}

fig = plt.figure(figsize=(18, 15))

plt.subplot(2, 3, 1)
for algo in sorted(df['display_name'].unique()):
    algo_data = df[df['display_name'] == algo]
    if algo_data.empty:
        continue
        
    algo_data = algo_data.sort_values('size')
    
    linestyle = '--' if 'kway' in algo else '-'
    color = algo_colors.get(algo, 'black')
    
    plt.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
             color=color, linewidth=2, markersize=6, label=algo)

plt.xlabel('Array Size (N)', fontsize=12)
plt.ylabel('Execution Time (s)', fontsize=12)
plt.title('Standard Scale', fontsize=14)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(fontsize=10)
plt.xticks(fontsize=10)
plt.yticks(fontsize=10)

plt.subplot(2, 3, 2)
for algo in sorted(df['display_name'].unique()):
    algo_data = df[df['display_name'] == algo]
    if algo_data.empty:
        continue
        
    algo_data = algo_data.sort_values('size')
    
    linestyle = '--' if 'kway' in algo else '-'
    color = algo_colors.get(algo, 'black')
    
    plt.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
             color=color, linewidth=2, markersize=6, label=algo)

plt.xlabel('Array Size (N)', fontsize=12)
plt.ylabel('Execution Time (s)', fontsize=12)
plt.title('Log Scale', fontsize=14)
plt.grid(True, linestyle='--', alpha=0.7)
plt.yscale('log')
plt.legend(fontsize=10)
plt.xticks(fontsize=10)
plt.yticks(fontsize=10)

plt.subplot(2, 3, 3)
markers = ['o', 's', '^']
for i, k in enumerate([2, 3, 5]):
    k_data = df_kway[df_kway['k_value'] == k]
    if k_data.empty:
        continue
        
    k_data = k_data.sort_values('size')
    color = algo_colors.get(f'kway (k={k})', 'black')
    
    plt.plot(k_data['size'], k_data['time'], marker=markers[i], linestyle='--', 
             color=color, linewidth=2, markersize=6, label=f'kway (k={k})')

plt.xlabel('Array Size (N)', fontsize=12)
plt.ylabel('Execution Time (s)', fontsize=12)
plt.title('K-Way Comparison', fontsize=14)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(fontsize=10)
plt.xticks(fontsize=10)
plt.yticks(fontsize=10)

gs = gridspec.GridSpec(3, 1, height_ratios=[1, 3, 1], hspace=0)
ax_top = plt.subplot(gs[0])
ax_bottom = plt.subplot(gs[1])
plt.subplot(2, 3, 4)

threshold = min_time * 5
for algo in sorted(df['display_name'].unique()):
    algo_data = df[df['display_name'] == algo]
    if algo_data.empty:
        continue
        
    algo_data = algo_data.sort_values('size')
    
    linestyle = '--' if 'kway' in algo else '-'
    color = algo_colors.get(algo, 'black')
    
    ax_top.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
             color=color, linewidth=2, markersize=6, label=algo)
    ax_bottom.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
               color=color, linewidth=2, markersize=6, label=algo)

ax_top.set_ylim(bottom=threshold, top=max_time * 1.1)
ax_bottom.set_ylim(bottom=0, top=threshold)

ax_bottom.set_xlabel('Array Size (N)', fontsize=12)
ax_bottom.set_ylabel('Execution Time (s)', fontsize=12)
ax_top.set_title('Broken Y-axis', fontsize=14)

d = .015
kwargs = dict(transform=ax_top.transAxes, color='k', clip_on=False)
ax_top.plot((-d, +d), (-d, +d), **kwargs)
ax_top.plot((1 - d, 1 + d), (-d, +d), **kwargs)

kwargs.update(transform=ax_bottom.transAxes)
ax_bottom.plot((-d, +d), (1 - d, 1 + d), **kwargs)
ax_bottom.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

ax_top.legend(fontsize=10)
ax_top.grid(True, linestyle='--', alpha=0.7)
ax_bottom.grid(True, linestyle='--', alpha=0.7)

plt.subplot(2, 3, 5)
base_algos = ['ours', 'ours_hybrid', 'mehp24']
for algo in base_algos:
    algo_data = df_base[df_base['algorithm'] == algo]
    if algo_data.empty:
        continue
    
    algo_data = algo_data.sort_values('size')
    
    color = algo_colors.get(algo, 'black')
    plt.plot(algo_data['size'], algo_data['time'], marker='o', color=color, 
             linewidth=2, markersize=6, label=algo)

plt.xlabel('Array Size (N)', fontsize=12)
plt.ylabel('Execution Time (s)', fontsize=12)
plt.title('Base Algorithms Comparison', fontsize=14)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(fontsize=10)
plt.xticks(fontsize=10)
plt.yticks(fontsize=10)

plt.subplot(2, 3, 6)
common_sizes = [size for size in df_base['size'].unique() if size in df_kway['size'].unique()]
comparison_data = []

for size in sorted(common_sizes):
    for algo in base_algos:
        base_time = df_base[(df_base['algorithm'] == algo) & (df_base['size'] == size)]['time'].values
        if len(base_time) > 0:
            base_time = base_time[0]
            
            for k_value in [2, 3, 5]:
                kway_data = df_kway[(df_kway['k_value'] == k_value) & (df_kway['size'] == size)]
                if not kway_data.empty:
                    kway_time = kway_data['time'].values[0]
                    speedup = kway_time / base_time
                    comparison_data.append({
                        'size': size,
                        'base_algo': algo,
                        'k_value': k_value,
                        'speedup': speedup
                    })

if comparison_data:
    comparison_df = pd.DataFrame(comparison_data)
    
    for algo in base_algos:
        for k in [2, 3, 5]:
            data = comparison_df[(comparison_df['base_algo'] == algo) & (comparison_df['k_value'] == k)]
            if not data.empty:
                plt.plot(data['size'], data['speedup'], marker='o', linestyle='-',
                         label=f'{algo} vs kway k={k}')

    plt.axhline(y=1.0, color='black', linestyle='--')
    plt.xlabel('Array Size (N)', fontsize=12)
    plt.ylabel('Speedup (kway/base)', fontsize=12)
    plt.title('Performance Ratio', fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=8)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)

plt.suptitle('FHE Sorting Algorithms Performance Comparison', fontsize=16)
plt.tight_layout(rect=[0, 0, 1, 0.97])

plt.savefig(os.path.join(script_dir, 'algorithm_comparison_combined.png'), dpi=300)
print("Saved: algorithm_comparison_combined.png")

print("All plots have been saved successfully.")