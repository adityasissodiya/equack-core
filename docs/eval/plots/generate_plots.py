#!/usr/bin/env python3
"""
Generate evaluation plots from CSV data.
Requires: matplotlib, numpy
Install: pip install matplotlib numpy
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent
DPI = 180

def plot_e6_scaling():
    """E6: Replay Time Scaling with linear fit."""
    data = pd.read_csv(OUTPUT_DIR / 'plot-data-e6-scaling.csv')

    fig, ax = plt.subplots(figsize=(8, 6))

    # Plot data points
    ax.scatter(data['operations'], data['replay_full_ms'],
               s=100, label='Full Replay', zorder=3, color='#1f77b4')
    ax.scatter(data['operations'], data['replay_incremental_ms'],
               s=100, label='Incremental Replay', zorder=3, color='#ff7f0e')

    # Linear fit for full replay
    coeffs = np.polyfit(data['operations'], data['replay_full_ms'], 1)
    fit_line = np.poly1d(coeffs)
    ax.plot(data['operations'], fit_line(data['operations']),
            '--', color='gray', alpha=0.7,
            label=f'Linear fit: t = {coeffs[0]:.4f}n + {coeffs[1]:.1f}')

    ax.set_xlabel('Operations')
    ax.set_ylabel('Replay Time (ms)')
    ax.set_title('E6: Replay Time Scaling (Linear)')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'fig-e6-scaling.png', dpi=DPI, bbox_inches='tight')
    plt.close()
    print(f"✓ Generated {OUTPUT_DIR / 'fig-e6-scaling.png'}")


def plot_e7_throughput():
    """E7: Throughput Comparison by Scenario."""
    data = pd.read_csv(OUTPUT_DIR / 'plot-data-e7-throughput.csv')
    data = data.sort_values('throughput_ops_per_sec')

    fig, ax = plt.subplots(figsize=(10, 6))

    colors = {'hb-chain': '#1f77b4', 'concurrent': '#ff7f0e', 'offline-revocation': '#2ca02c'}
    bar_colors = [colors.get(s, '#999999') for s in data['scenario']]

    bars = ax.barh(data['scenario'], data['throughput_ops_per_sec'], color=bar_colors)

    # Add value labels
    for bar in bars:
        width = bar.get_width()
        ax.text(width + max(data['throughput_ops_per_sec'])*0.02, bar.get_y() + bar.get_height()/2,
                f'{int(width):,}', ha='left', va='center', fontsize=10)

    ax.set_xlabel('Throughput (ops/s)')
    ax.set_ylabel('Scenario')
    ax.set_title('E7: Replay Throughput by Scenario')
    ax.grid(True, alpha=0.3, axis='x')

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'fig-e7-throughput.png', dpi=DPI, bbox_inches='tight')
    plt.close()
    print(f"✓ Generated {OUTPUT_DIR / 'fig-e7-throughput.png'}")


def plot_e10_speedup():
    """E10: Checkpoint Speedup Factors."""
    data = pd.read_csv(OUTPUT_DIR / 'plot-data-e10-speedup.csv')

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(range(len(data)), data['speedup_factor'], color='#2ca02c')
    ax.set_xticks(range(len(data)))
    ax.set_xticklabels([f"{int(ops):,}" for ops in data['operations']])

    # Add value labels
    for bar, val in zip(bars, data['speedup_factor']):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(data['speedup_factor'])*0.02,
                f'{val:.1f}x', ha='center', va='bottom', fontsize=12, fontweight='bold')

    ax.set_xlabel('Operations')
    ax.set_ylabel('Speedup Factor (x)')
    ax.set_title('E10: Checkpoint Speedup (Full / Incremental)')
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'fig-e10-checkpoint-speedup.png', dpi=DPI, bbox_inches='tight')
    plt.close()
    print(f"✓ Generated {OUTPUT_DIR / 'fig-e10-checkpoint-speedup.png'}")


if __name__ == '__main__':
    print("Generating evaluation plots...")
    plot_e6_scaling()
    plot_e7_throughput()
    plot_e10_speedup()
    print("\nAll plots generated successfully!")
    print(f"Output directory: {OUTPUT_DIR}")
