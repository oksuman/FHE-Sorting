#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
TEST_DIR="$PROJECT_ROOT/build/tests"
NUM_TRIALS=10

mkdir -p "$SCRIPT_DIR/experimental_results/mehp24"
mkdir -p "$SCRIPT_DIR/experimental_results/ours"
mkdir -p "$SCRIPT_DIR/experimental_results/ours_hybrid"
mkdir -p "$SCRIPT_DIR/experimental_results/kway"

format_results() {
    local algo=$1
    local size=$2
    local summary_file="${SCRIPT_DIR}/experimental_results/${algo}/N${size}_summary.txt"
    local total_file="${SCRIPT_DIR}/experimental_results/${algo}/total_results.txt"
    local detail_file="${SCRIPT_DIR}/experimental_results/${algo}/N${size}_details.txt"
    local temp_dir="${SCRIPT_DIR}/experimental_results/${algo}/temp_N${size}"

    local avg_time=$(awk '/Execution time:/ {sum+=$3} END {printf "%.2f", sum/NR/1000}' ${temp_dir}/trial_*.txt)
    local avg_max_err=$(awk '/Maximum error:/ {sum+=$3} END {printf "%.6f", sum/NR}' ${temp_dir}/trial_*.txt)
    local avg_avg_err=$(awk '/Average error:/ {sum+=$3} END {printf "%.6f", sum/NR}' ${temp_dir}/trial_*.txt)
    local ring_dim=$(grep "Ring Dimension:" ${temp_dir}/trial_1.txt | awk '{print $3}')
    local mult_depth=$(grep "Multiplicative depth:" ${temp_dir}/trial_1.txt | awk '{print $3}')
    local scale_mod=$(grep "Scaling Mod:" ${temp_dir}/trial_1.txt | awk '{print $3}')

    local n_value=3
    local dg_value=$(awk -v n=$size 'BEGIN {if (n <= 16) print 2; else if (n <= 128) print 3; else if (n <= 512) print 4; else print 5}')
    local df_value=2

    echo "======================================" > "$summary_file"
    echo "     Results for N = $size" >> "$summary_file"
    echo "======================================" >> "$summary_file"
    echo "Crypto Parameters:" >> "$summary_file"
    echo "  Ring Dimension      : $ring_dim" >> "$summary_file"
    echo "  Multiplicative Depth: $mult_depth" >> "$summary_file"
    echo "  Scaling Mod Size    : $scale_mod" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Sign Configuration:" >> "$summary_file"
    echo "  Degree: $n_value" >> "$summary_file"
    echo "  dg    : $dg_value" >> "$summary_file"
    echo "  df    : $df_value" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Performance Metrics:" >> "$summary_file"
    echo "  Average Time     : $avg_time s" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Error Analysis:" >> "$summary_file"
    echo "  Max Error        : $avg_max_err (log2: $(echo "l($avg_max_err)/l(2)" | bc -l))" >> "$summary_file"
    echo "  Average Error    : $avg_avg_err (log2: $(echo "l($avg_avg_err)/l(2)" | bc -l))" >> "$summary_file"
    echo "======================================" >> "$summary_file"

    cat "$summary_file" >> "$total_file"

    echo "Trial Results for N=$size" > "$detail_file"
    echo "Trial\tTime(ms)\tMaxErr\tAvgErr" >> "$detail_file"
    for trial_file in ${temp_dir}/trial_*.txt; do
        local trial_num=$(basename "$trial_file" | grep -o '[0-9]\+')
        local time=$(grep 'Execution time:' "$trial_file" | awk '{print $3}')
        local max_err=$(grep 'Maximum error:' "$trial_file" | awk '{print $3}')
        local avg_err=$(grep 'Average error:' "$trial_file" | awk '{print $3}')
        echo -e "$trial_num\t$time\t$max_err\t$avg_err" >> "$detail_file"
    done
}

run_test() {
    local algo=$1
    local test_executable=$2
    local sizes=()

    case $algo in
        "kway")
            sizes=(9 16 25 27 32 64 81 125 128 243 512 625 729 1024 2048 2187)
            ;;
        *)
            sizes=(4 8 16 32 64 128 256 512 1024)
            ;;
    esac

    echo "Running $algo tests"
    cd "$TEST_DIR" || exit 1

    for size in "${sizes[@]}"; do
        for ((trial=1; trial<=$NUM_TRIALS; trial++)); do
            echo "Trial $trial of $NUM_TRIALS for N=$size"
            local output_dir="${SCRIPT_DIR}/experimental_results/${algo}/temp_N$size"
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
        format_results $algo $size
        rm -rf "${SCRIPT_DIR}/experimental_results/${algo}/temp_N$size"
    done
}

if [ ! -d "$TEST_DIR" ]; then
    echo "Error: Test directory not found: $TEST_DIR"
    exit 1
fi

cd "$TEST_DIR" || exit 1


# can comment out
run_test "ours_hybrid" "DirectSortHTest"
run_test "mehp24" "Mehp24SortTest"
run_test "ours" "DirectSortTest"
run_test "kway" "KWaySort235Test"

echo "All experiments completed!"

# chmod +x run_experiments.sh
# ./run_experiments.sh
