# Evaluation Plots Data

This directory contains plot data extracted from benchmark results. Matplotlib is not available in the current environment, so plot data is provided in CSV format for visualization using external tools.

## Plot Data Files

### 1. E6: Replay Time Scaling (`plot-data-e6-scaling.csv`)
**Purpose**: Show linear scaling of replay time with operation count

**Columns**:
- `operations`: Total operation count
- `replay_full_ms`: Full replay time in milliseconds
- `replay_incremental_ms`: Incremental replay time in milliseconds

**Visualization**: Line plot with linear regression fit
- X-axis: Operations
- Y-axis: Replay time (ms)
- Two series: Full replay and Incremental replay
- Add linear fit line: t = 0.019n + 120, R² = 0.998

### 2. E7: Throughput Comparison (`plot-data-e7-throughput.csv`)
**Purpose**: Compare throughput across scenarios

**Columns**:
- `scenario`: Benchmark scenario name
- `throughput_ops_per_sec`: Operations per second

**Visualization**: Horizontal bar chart
- X-axis: Throughput (ops/s)
- Y-axis: Scenario names
- Color-code bars by scenario type

### 3. E10: Checkpoint Speedup (`plot-data-e10-speedup.csv`)
**Purpose**: Show checkpoint efficiency gains

**Columns**:
- `operations`: Total operation count
- `speedup_factor`: Speedup ratio (full / incremental)

**Visualization**: Vertical bar chart
- X-axis: Operations
- Y-axis: Speedup factor (x)
- Add value labels on top of bars

## Generating Plots

### Option 1: Using Python (if matplotlib available)
```bash
# Install dependencies
pip install matplotlib numpy pandas

# Run plot script
python3 ../../tools/scripts/plot.py ../out/perf .
```

### Option 2: Using R
```r
library(ggplot2)

# E6 Scaling
data <- read.csv("plot-data-e6-scaling.csv")
ggplot(data, aes(x=operations)) +
  geom_point(aes(y=replay_full_ms, color="Full"), size=3) +
  geom_point(aes(y=replay_incremental_ms, color="Incremental"), size=3) +
  geom_smooth(aes(y=replay_full_ms), method="lm", se=FALSE) +
  labs(title="E6: Replay Time Scaling", x="Operations", y="Time (ms)") +
  theme_minimal()
ggsave("fig-e6-scaling.png", width=8, height=6, dpi=180)

# E7 Throughput
data <- read.csv("plot-data-e7-throughput.csv")
ggplot(data, aes(x=reorder(scenario, throughput_ops_per_sec), y=throughput_ops_per_sec)) +
  geom_bar(stat="identity", fill="steelblue") +
  coord_flip() +
  labs(title="E7: Throughput by Scenario", x="Scenario", y="Throughput (ops/s)") +
  theme_minimal()
ggsave("fig-e7-throughput.png", width=10, height=6, dpi=180)

# E10 Speedup
data <- read.csv("plot-data-e10-speedup.csv")
ggplot(data, aes(x=factor(operations), y=speedup_factor)) +
  geom_bar(stat="identity", fill="forestgreen") +
  geom_text(aes(label=sprintf("%.1fx", speedup_factor)), vjust=-0.5) +
  labs(title="E10: Checkpoint Speedup", x="Operations", y="Speedup Factor") +
  theme_minimal()
ggsave("fig-e10-checkpoint-speedup.png", width=8, height=6, dpi=180)
```

### Option 3: Using Excel/LibreOffice
1. Open each CSV file in Excel/LibreOffice Calc
2. Select data columns
3. Insert → Chart → Select appropriate chart type
4. Export as PNG at 180 DPI

### Option 4: Using gnuplot
```gnuplot
# E6 Scaling
set terminal png size 1200,800
set output 'fig-e6-scaling.png'
set xlabel 'Operations'
set ylabel 'Replay Time (ms)'
set title 'E6: Replay Time Scaling'
set grid
plot 'plot-data-e6-scaling.csv' using 1:2 with linespoints title 'Full Replay', \
     '' using 1:3 with linespoints title 'Incremental Replay'
```

## Expected Output Files

After visualization, you should have:
- `fig-e6-scaling.png` - E6 replay time scaling plot
- `fig-e7-throughput.png` - E7 throughput comparison
- `fig-e10-checkpoint-speedup.png` - E10 checkpoint speedup bars
- `fig-replay-cost.png` - General replay cost plot (from plot.py)
- `fig-rollback-rate.png` - Rollback rate plot (from plot.py)

## Notes

- All CSV files use comma delimiters
- Header row included in each file
- Values are medians across benchmark runs with seed=42
- Plots should use 180 DPI for publication quality
- Recommended size: 8x6 inches for individual plots, 10x6 for comparison charts
