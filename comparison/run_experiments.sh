#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
TEST_DIR="$PROJECT_ROOT/build/tests"
NUM_TRIALS=10

mkdir -p "$SCRIPT_DIR/mehp24"
mkdir -p "$SCRIPT_DIR/ours"
mkdir -p "$SCRIPT_DIR/ours_hybrid"
mkdir -p "$SCRIPT_DIR/kway"

format_results() {
   local algo=$1
   local size=$2
   local summary_file="${SCRIPT_DIR}/${algo}/N${size}_summary.txt"
   local total_file="${SCRIPT_DIR}/${algo}/total_results.txt"
   local temp_dir="${SCRIPT_DIR}/${algo}/temp_N${size}"
   
   local avg_time=$(awk '/Execution time:/ {sum+=$3} END {printf "%.2f", sum/NR/1000}' ${temp_dir}/trial_*.txt)
   local avg_max_err=$(awk '/Maximum error:/ {sum+=$3} END {printf "%.6f", sum/NR}' ${temp_dir}/trial_*.txt)
   local avg_avg_err=$(awk '/Average error:/ {sum+=$3} END {printf "%.6f", sum/NR}' ${temp_dir}/trial_*.txt)
   
   local ring_dim=$(grep "Ring Dimension:" ${temp_dir}/trial_1.txt | awk '{print $4}')
   local mult_depth=$(grep "Multiplicative depth:" ${temp_dir}/trial_1.txt | awk '{print $3}')
   local scale_mod=$(grep "Scaling Mod:" ${temp_dir}/trial_1.txt | awk '{print $3}')
   local n_value=3
   local dg_value=$(awk -v n=$size 'BEGIN {if (n <= 16) print 2; else if (n <= 128) print 3; else if (n <= 512) print 4; else print 5}')
   local df_value=2
   
   {
       echo "Array Size (N): $size"
       echo "Ring Dimension: $ring_dim"
       echo "Multiplicative Depth: $mult_depth"
       echo "Scaling Mod Size: $scale_mod"
       echo "Sign Configuration (degree, dg, df): ($n_value, $dg_value, $df_value)"
       echo "Average Execution Time: $avg_time s"
       echo "Average Maximum Error: $avg_max_err"
       echo "Average Maximum Error (log2): $(echo "l($avg_max_err)/l(2)" | bc -l)"
       echo "Average Average Error: $avg_avg_err"
       echo "Average Average Error (log2): $(echo "l($avg_avg_err)/l(2)" | bc -l)"
       echo "----------------------------------------"
   } > "$summary_file"
   
   cat "$summary_file" >> "$total_file"
}

run_test() {
   local algo=$1
   local test_executable=$2
   
   echo "Running $algo tests"
   
   cd "$TEST_DIR" || exit 1
   
   for ((trial=1; trial<=$NUM_TRIALS; trial++)); do
       echo "Trial $trial of $NUM_TRIALS"
       
       local output_dir="${SCRIPT_DIR}/${algo}/temp_N$size"
       mkdir -p "$output_dir"
       
       case $algo in
           "ours_hybrid")
               ./$test_executable > "${output_dir}/trial_${trial}.txt"
               ;;
           "mehp24")
               ./mehp24/$test_executable > "${output_dir}/trial_${trial}.txt"
               ;;
           "ours")
               ./$test_executable > "${output_dir}/trial_${trial}.txt"
               ;;
           "kway")
               ./k-way/$test_executable > "${output_dir}/trial_${trial}.txt"
               ;;
       esac
   done
   
   for temp_dir in "${SCRIPT_DIR}/${algo}"/temp_N*; do
       if [ -d "$temp_dir" ]; then
           local size=$(echo $temp_dir | grep -o 'N[0-9]*' | grep -o '[0-9]*')
           format_results $algo $size
           rm -rf "$temp_dir"
       fi
   done
}

if [ ! -d "$TEST_DIR" ]; then
   echo "Error: Test directory not found: $TEST_DIR"
   exit 1
fi

cd "$TEST_DIR" || exit 1

run_test "ours_hybrid" "DirectSortHTest"
run_test "mehp24" "Mehp24SortTest"
run_test "ours" "DirectSortTest"
run_test "kway" "KWaySort235Test"

echo "All experiments completed!"

# chmod +x run_experiments.sh
# ./run_experiments.sh
