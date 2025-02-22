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

algorithms = ['ours', 'ours_hybrid', 'mehp24', 'kway']

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
                time = float(time_match.group(1)) * 1000  # Convert seconds to milliseconds
                
                k_value = None
                if algo == 'kway':
                    k_match = re.search(r'Sign Configuration\s*:.*?k=(\d+)', content)
                    if k_match:
                        k_value = int(k_match.group(1))
                
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

df_avg = df.groupby(['algorithm', 'k_value', 'size']).mean().reset_index()

df_merged = df_avg.copy()
for k in [2, 3, 5]:
    k_rows = df_avg[(df_avg['algorithm'] == 'kway') & (df_avg['k_value'] == k)]
    if not k_rows.empty:
        k_rows = k_rows.copy()
        k_rows['algorithm'] = f'kway (k={k})'
        df_merged = pd.concat([df_merged, k_rows])

print("\nAlgorithms found in data:")
for algo in df_merged['algorithm'].unique():
    count = len(df_merged[df_merged['algorithm'] == algo])
    print(f"Algorithm: {algo}, Data points: {count}")

min_time = df_merged['time'].min()
max_time = df_merged['time'].max()

algo_colors = {
    'ours': 'blue',
    'ours_hybrid': 'green',
    'mehp24': 'red',
    'kway (k=2)': 'purple',
    'kway (k=3)': 'orange',
    'kway (k=5)': 'brown'
}

plt.figure(figsize=(12, 8))

for algo in sorted(df_merged['algorithm'].unique()):
    if algo == 'kway':
        continue
        
    algo_data = df_merged[df_merged['algorithm'] == algo]
    if algo_data.empty:
        print(f"No data points for algorithm: {algo}")
        continue
        
    algo_data = algo_data.sort_values('size')
    
    linestyle = '--' if 'kway' in algo else '-'
    color = algo_colors.get(algo, 'black')
    
    plt.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
             color=color, linewidth=2, markersize=8, label=algo)

plt.xlabel('Array Size (N)', fontsize=14)
plt.ylabel('Execution Time (ms)', fontsize=14)
plt.title('Comparison of FHE Sorting Algorithm Execution Times', fontsize=16)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(fontsize=12)
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
plt.tight_layout()
plt.savefig(os.path.join(script_dir, 'algorithm_comparison.png'), dpi=300)
print("Saved: algorithm_comparison.png")

plt.figure(figsize=(12, 8))

for algo in sorted(df_merged['algorithm'].unique()):
    if algo == 'kway':
        continue
        
    algo_data = df_merged[df_merged['algorithm'] == algo]
    if algo_data.empty:
        continue
        
    algo_data = algo_data.sort_values('size')
    
    linestyle = '--' if 'kway' in algo else '-'
    color = algo_colors.get(algo, 'black')
    
    plt.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
             color=color, linewidth=2, markersize=8, label=algo)

plt.xlabel('Array Size (N)', fontsize=14)
plt.ylabel('Execution Time (ms)', fontsize=14)
plt.title('Comparison of FHE Sorting Algorithms (Log Scale)', fontsize=16)
plt.grid(True, linestyle='--', alpha=0.7)
plt.yscale('log')
plt.legend(fontsize=12)
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
plt.tight_layout()
plt.savefig(os.path.join(script_dir, 'algorithm_comparison_log.png'), dpi=300)
print("Saved: algorithm_comparison_log.png")

ratio = max_time / min_time if min_time > 0 else 1
if ratio > 15:
    fig = plt.figure(figsize=(12, 10))
    gs = gridspec.GridSpec(2, 1, height_ratios=[1, 3])
    
    ax_top = plt.subplot(gs[0])
    ax_bottom = plt.subplot(gs[1])
    
    threshold = min_time * 5
    
    for algo in sorted(df_merged['algorithm'].unique()):
        if algo == 'kway':
            continue
            
        algo_data = df_merged[df_merged['algorithm'] == algo]
        if algo_data.empty:
            continue
            
        algo_data = algo_data.sort_values('size')
        
        linestyle = '--' if 'kway' in algo else '-'
        color = algo_colors.get(algo, 'black')
        
        ax_top.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
                 color=color, linewidth=2, markersize=8, label=algo)
        ax_bottom.plot(algo_data['size'], algo_data['time'], marker='o', linestyle=linestyle, 
                   color=color, linewidth=2, markersize=8, label=algo)
    
    ax_top.set_ylim(bottom=threshold, top=max_time * 1.1)
    ax_bottom.set_ylim(bottom=0, top=threshold)
    
    ax_bottom.set_xlabel('Array Size (N)', fontsize=14)
    ax_bottom.set_ylabel('Execution Time (ms)', fontsize=14)
    ax_top.set_title('Comparison with Broken Y-axis', fontsize=16)
    
    d = .015
    kwargs = dict(transform=ax_top.transAxes, color='k', clip_on=False)
    ax_top.plot((-d, +d), (-d, +d), **kwargs)
    ax_top.plot((1 - d, 1 + d), (-d, +d), **kwargs)
    
    kwargs.update(transform=ax_bottom.transAxes)
    ax_bottom.plot((-d, +d), (1 - d, 1 + d), **kwargs)
    ax_bottom.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)
    
    ax_top.legend(fontsize=12)
    ax_top.grid(True, linestyle='--', alpha=0.7)
    ax_bottom.grid(True, linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig(os.path.join(script_dir, 'algorithm_comparison_broken.png'), dpi=300)
    print("Saved: algorithm_comparison_broken.png")

plt.figure(figsize=(12, 8))

base_algos = ['ours', 'ours_hybrid', 'mehp24']
base_algo_data = []

for algo in base_algos:
    algo_data = df_avg[df_avg['algorithm'] == algo]
    if algo_data.empty:
        print(f"No data for base algorithm: {algo}")
        continue
        
    algo_data = algo_data.sort_values('size')
    base_algo_data.append(algo_data)
    
    color = algo_colors.get(algo, 'black')
    plt.plot(algo_data['size'], algo_data['time'], marker='o', color=color, 
             linewidth=2, markersize=8, label=algo)

plt.xlabel('Array Size (N)', fontsize=14)
plt.ylabel('Execution Time (ms)', fontsize=14)
plt.title('Main Algorithms vs. k-way by k-value', fontsize=16)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(fontsize=12)

twin_axes = []
kway_plotted = False

for i, k in enumerate([2, 3, 5]):
    k_data = df_avg[(df_avg['algorithm'] == 'kway') & (df_avg['k_value'] == k)]
    if k_data.empty:
        print(f"No data for kway with k={k}")
        continue
    
    kway_plotted = True
        
    if i == 0:
        ax = plt.gca()
    else:
        ax = plt.twinx()
        ax.spines['right'].set_position(('outward', 60 * (i-1)))
        twin_axes.append(ax)
    
    k_data = k_data.sort_values('size')
    color = algo_colors.get(f'kway (k={k})', 'black')
    ax.plot(k_data['size'], k_data['time'], marker='s', linestyle='--', 
            color=color, linewidth=2, markersize=8, label=f'kway (k={k})')
    ax.set_ylabel(f'Time for k={k} (ms)', color=color, fontsize=14)
    ax.tick_params(axis='y', labelcolor=color)
    ax.legend(fontsize=12)

if len(base_algo_data) > 0 and kway_plotted:
    plt.tight_layout()
    plt.savefig(os.path.join(script_dir, 'algorithms_by_k_value.png'), dpi=300)
    print("Saved: algorithms_by_k_value.png")
else:
    print("Warning: Could not create algorithms_by_k_value.png due to missing data")

print("All plots have been saved successfully.")