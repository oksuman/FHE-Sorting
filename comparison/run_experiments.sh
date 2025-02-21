#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
TEST_DIR="$PROJECT_ROOT/build/tests"
NUM_TRIALS=1

mkdir -p "$SCRIPT_DIR/experimental_results/mehp24"
mkdir -p "$SCRIPT_DIR/experimental_results/ours"
mkdir -p "$SCRIPT_DIR/experimental_results/ours_hybrid"
mkdir -p "$SCRIPT_DIR/experimental_results/kway"

DIRECT_SIZES=(4 8 16 32 64)
MEHP24_SIZES=(4 8 16 32 64)
KWAY_SIZES=(9 16 25 27 32 64 81 125 128 243 256 512 625)

extract_test_results() {
    local input_file=$1
    local output_dir=$2
    
    local sizes=($(grep "^Input array size:" "$input_file" | awk '{print $4}'))
    
    if [ ${#sizes[@]} -eq 0 ]; then
        echo "Warning: No 'Input array size:' patterns found in $input_file"
        return
    fi
    
    for i in "${!sizes[@]}"; do
        local size=${sizes[$i]}
        echo "Processing results for size: $size"
        
        local size_file="${output_dir}/size_${size}.txt"
        > "$size_file"
        
        local start_pattern="Input array size: ${size}"
        
        if [ $((i+1)) -lt ${#sizes[@]} ]; then
            local next_size=${sizes[$((i+1))]}
            local end_pattern="Input array size: ${next_size}"
            
            awk -v start="$start_pattern" -v end="$end_pattern" \
                'BEGIN {found=0} 
                $0 ~ start {found=1} 
                found && $0 !~ end {print} 
                $0 ~ end {found=0}' "$input_file" > "$size_file"
        else
            awk -v start="$start_pattern" \
                'BEGIN {found=0} 
                $0 ~ start {found=1} 
                found {print}' "$input_file" > "$size_file"
        fi
    done
}

get_kway_params() {
    local size=$1
    case $size in
        9) echo "k=3, M=2, d_f=2, d_g=2" ;;
        16) echo "k=2, M=4, d_f=2, d_g=2" ;;
        25) echo "k=5, M=2, d_f=2, d_g=3" ;;
        27) echo "k=3, M=3, d_f=2, d_g=3" ;;
        32) echo "k=2, M=5, d_f=2, d_g=3" ;;
        64) echo "k=2, M=6, d_f=2, d_g=3" ;;
        81) echo "k=3, M=4, d_f=2, d_g=3" ;;
        125) echo "k=5, M=3, d_f=2, d_g=3" ;;
        128) echo "k=2, M=7, d_f=2, d_g=4" ;;
        243) echo "k=3, M=5, d_f=2, d_g=4" ;;
        256) echo "k=2, M=8, d_f=2, d_g=4" ;;
        512) echo "k=2, M=9, d_f=2, d_g=4" ;;
        625) echo "k=5, M=4, d_f=2, d_g=5" ;;
        729) echo "k=3, M=6, d_f=2, d_g=5" ;;
        1024) echo "k=2, M=10, d_f=2, d_g=5" ;;
        2048) echo "k=2, M=11, d_f=2, d_g=5" ;;
        2187) echo "k=3, M=7, d_f=2, d_g=5" ;;
        *) echo "unknown" ;;
    esac
}

format_results() {
    local algo=$1
    local size=$2
    local trial_dir=$3
    local summary_file="${SCRIPT_DIR}/experimental_results/${algo}/N${size}_summary.txt"
    local total_file="${SCRIPT_DIR}/experimental_results/${algo}/total_results.txt"
    
    > "$summary_file"
    
    local ring_dim=""
    local mult_depth=""
    local scale_mod=""
    local sign_config=""
    local times=()
    local max_err_logs=()
    local avg_err_logs=()
    
    local found_results=false
    
    for trial in $(seq 1 $NUM_TRIALS); do
        local result_file="${trial_dir}/trial_${trial}/size_${size}.txt"
        if [[ -f "$result_file" && -s "$result_file" ]]; then
            found_results=true
            
            if [[ -z "$ring_dim" ]]; then
                ring_dim=$(grep -m1 "Using Ring Dimension:" "$result_file" | awk '{print $4}')
                mult_depth=$(grep -m1 "Multiplicative depth:" "$result_file" | awk '{print $3}')
                scale_mod=$(grep -m1 "Scaling Mod:" "$result_file" | awk '{print $3}')
                
                sign_config_line=$(grep -m1 "Sign Configuration:" "$result_file" 2>/dev/null)
                
                if [[ -n "$sign_config_line" ]]; then
                    sign_config=$(echo "$sign_config_line" | sed 's/Sign Configuration: //')
                else
                    if [[ "$algo" == "kway" ]]; then
                        sign_config="CompositeSign(3, $(get_kway_params $size))"
                    else
                        if [[ $size -le 16 ]]; then
                            sign_config="CompositeSign(3, 2, 2)"
                        elif [[ $size -le 128 ]]; then
                            sign_config="CompositeSign(3, 3, 2)"
                        elif [[ $size -le 512 ]]; then
                            sign_config="CompositeSign(3, 4, 2)"
                        else
                            sign_config="CompositeSign(3, 5, 2)"
                        fi
                        
                        if [[ "$algo" == "mehp24" ]]; then
                            local dg_i=$(echo "scale=0; (l($size)/l(2) + 1)/2" | bc -l)
                            sign_config="$sign_config, dg_i=$dg_i, df_i=2"
                        fi
                    fi
                fi
                
                ring_dim=${ring_dim:-"N/A"}
                mult_depth=${mult_depth:-"N/A"}
                scale_mod=${scale_mod:-"N/A"}
                sign_config=${sign_config:-"N/A"}
            fi
            
            # 실행 시간 값을 추출 (ms 단위)
            local time=$(grep -m1 "Execution time:" "$result_file" | awk '{print $3}')
            local max_err_log=$(grep -m1 "Maximum error:" "$result_file" | awk -F'log2: ' '{print $2}' | tr -d ')')
            local avg_err_log=$(grep -m1 "Average error:" "$result_file" | awk -F'log2: ' '{print $2}' | tr -d ')')

            if [[ "$max_err_log" != "N/A" && "$max_err_log" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
                max_err_logs+=($max_err_log)
            fi

            if [[ "$avg_err_log" != "N/A" && "$avg_err_log" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
                avg_err_logs+=($avg_err_log)
            fi

            if [[ -n "$time" ]]; then
                times+=($time)
            fi
        fi
    done
    
    if [[ "$found_results" == "false" ]]; then
        echo "No valid results found for $algo with N=$size"
        return
    fi
    
    local n_trials=${#times[@]}
    if [[ $n_trials -eq 0 ]]; then
        echo "No timing data found for $algo with N=$size"
        return
    fi
    
    local avg_time="N/A"
    local avg_max_err_log="N/A"
    local avg_avg_err_log="N/A"
    
    if [[ $n_trials -gt 0 ]]; then
        local total_time=0
        for t in "${times[@]}"; do
            total_time=$(echo "$total_time + $t" | bc -l)
        done
        avg_time=$(echo "scale=4; $total_time / $n_trials / 1000" | bc -l)
        
        if [[ -z "$avg_time" || "$avg_time" == "0" ]]; then
            avg_time="N/A"
        fi
    fi
    
    if [[ ${#max_err_logs[@]} -gt 0 ]]; then
        local log_sum=0
        for log_val in "${max_err_logs[@]}"; do
            log_sum=$(echo "$log_sum + $log_val" | bc -l)
        done
        avg_max_err_log=$(echo "scale=4; $log_sum / ${#max_err_logs[@]}" | bc -l)
    fi
    
    if [[ ${#avg_err_logs[@]} -gt 0 ]]; then
        local log_sum=0
        for log_val in "${avg_err_logs[@]}"; do
            log_sum=$(echo "$log_sum + $log_val" | bc -l)
        done
        avg_avg_err_log=$(echo "scale=4; $log_sum / ${#avg_err_logs[@]}" | bc -l)
    fi
    
    echo "======================================" > "$summary_file"
    echo "     Results for N = $size" >> "$summary_file"
    echo "======================================" >> "$summary_file"
    echo "Crypto Parameters:" >> "$summary_file"
    echo "  Ring Dimension      : $ring_dim" >> "$summary_file"
    echo "  Multiplicative Depth: $mult_depth" >> "$summary_file"
    echo "  Scaling Mod Size    : $scale_mod" >> "$summary_file"
    echo "  Sign Configuration  : $sign_config" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Performance Metrics:" >> "$summary_file"sh
    echo "  Average Time     : ${avg_time}s" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Error Analysis:" >> "$summary_file"
    echo "  Max Error (log2): $avg_max_err_log" >> "$summary_file"
    echo "  Average Error (log2): $avg_avg_err_log" >> "$summary_file"
    echo "======================================" >> "$summary_file"
    
    cat "$summary_file" >> "$total_file"
    echo "" >> "$total_file"
    
    echo "Results for $algo with N=$size successfully processed"
}

run_test() {
    local algo=$1
    local test_executable=$2
    local sizes=("${@:3}")
    
    echo "Running $algo tests"
    cd "$TEST_DIR" || exit 1
    
    for trial in $(seq 1 $NUM_TRIALS); do
        echo "Trial $trial of $NUM_TRIALS"
        local trial_output_dir="${SCRIPT_DIR}/experimental_results/${algo}/trials/trial_${trial}"
        mkdir -p "$trial_output_dir"
        
        local executable_path="./$test_executable"
        
        echo "Executing: $executable_path"
        $executable_path > "${trial_output_dir}/output.txt" 2>&1
        extract_test_results "${trial_output_dir}/output.txt" "$trial_output_dir"
    done
    
    local trial_dir="${SCRIPT_DIR}/experimental_results/${algo}/trials"
    for size in "${sizes[@]}"; do
        format_results "$algo" "$size" "$trial_dir"
    done
}

generate_final_summary() {
    local final_summary="${SCRIPT_DIR}/experimental_results/final_summary.txt"
    local final_summary_md="${SCRIPT_DIR}/experimental_results/final_summary.md"
    
    echo "=========================================================" > "$final_summary"
    echo "               FINAL COMPARATIVE SUMMARY                  " >> "$final_summary"
    echo "=========================================================" >> "$final_summary"
    echo "" >> "$final_summary"
    
    echo "# FHE Sorting Algorithms Comparative Summary" > "$final_summary_md"
    echo "" >> "$final_summary_md"
    echo "## Performance Comparison" >> "$final_summary_md"
    
    for algo in "ours" "ours_hybrid" "mehp24" "kway"; do
        echo "" >> "$final_summary"
        echo "=== $algo Algorithm Summary ===" >> "$final_summary"
        echo "" >> "$final_summary"
        
        echo "" >> "$final_summary_md"
        echo "### ${algo} Algorithm" >> "$final_summary_md"
        echo "| Size  | Ring Dim | Mult Depth | Scale Mod | Sign Config                          | Avg Time (s) | Max Error (log2) | Avg Error (log2) |" >> "$final_summary_md"
        echo "|-------|----------|------------|-----------|------------------------------------- |--------------|------------------|------------------|" >> "$final_summary_md"
        
        local sizes
        case "$algo" in
            "ours"|"ours_hybrid"|"mehp24")
                sizes=("${DIRECT_SIZES[@]}")
                ;;
            "kway")
                sizes=("${KWAY_SIZES[@]}")
                ;;
        esac
        
        for size in "${sizes[@]}"; do
            local summary_file="${SCRIPT_DIR}/experimental_results/${algo}/N${size}_summary.txt"
            
            if [[ -f "$summary_file" ]]; then
                local ring_dim=$(grep "Ring Dimension" "$summary_file" | awk '{print $NF}')
                local mult_depth=$(grep "Multiplicative Depth" "$summary_file" | awk '{print $NF}')
                local scale_mod=$(grep "Scaling Mod Size" "$summary_file" | awk '{print $NF}')
                local sign_config=$(grep "Sign Configuration" "$summary_file" | awk -F': ' '{print $2}')
                
                local avg_time_line=$(grep "Average Time" "$summary_file")
                local avg_time=$(echo "$avg_time_line" | awk -F': ' '{print $2}')
                
                local max_err_log=$(grep "Max Error" "$summary_file" | awk '{print $NF}')
                local avg_err_log=$(grep "Average Error" "$summary_file" | awk '{print $NF}')
                
                echo "N = $size:" >> "$final_summary"
                echo "  Ring Dimension: $ring_dim" >> "$final_summary"
                echo "  Mult Depth: $mult_depth" >> "$final_summary"
                echo "  Scale Mod: $scale_mod" >> "$final_summary"
                echo "  Sign Config: $sign_config" >> "$final_summary"
                echo "  Avg Time: $avg_time" >> "$final_summary"
                echo "  Max Error (log2): $max_err_log" >> "$final_summary"
                echo "  Avg Error (log2): $avg_err_log" >> "$final_summary"
                echo "" >> "$final_summary"
                
                printf "| %-5s | %-8s | %-10s | %-9s | %-35s | %-12s | %-16s | %-16s |\n" "$size" "$ring_dim" "$mult_depth" "$scale_mod" "$sign_config" "$avg_time" "$max_err_log" "$avg_err_log" >> "$final_summary_md"
            fi
        done
    done
    
    echo "" >> "$final_summary_md"
    echo "## Cross-Algorithm Comparison" >> "$final_summary_md"
    
    local common_sizes=(16 32 64)
    
    for size in "${common_sizes[@]}"; do
        echo "" >> "$final_summary_md"
        echo "### Comparison for N = $size" >> "$final_summary_md"
        echo "| Algorithm   | Ring Dim | Mult Depth | Scale Mod | Avg Time (s) | Max Error (log2) | Avg Error (log2) |" >> "$final_summary_md"
        echo "|-------------|----------|------------|-----------|--------------|------------------|------------------|" >> "$final_summary_md"
        
        for algo in "ours" "ours_hybrid" "mehp24" "kway"; do
            local summary_file="${SCRIPT_DIR}/experimental_results/${algo}/N${size}_summary.txt"
            
            if [[ -f "$summary_file" ]]; then
                local ring_dim=$(grep "Ring Dimension" "$summary_file" | awk '{print $NF}')
                local mult_depth=$(grep "Multiplicative Depth" "$summary_file" | awk '{print $NF}')
                local scale_mod=$(grep "Scaling Mod Size" "$summary_file" | awk '{print $NF}')
                
                local avg_time_line=$(grep "Average Time" "$summary_file")
                local avg_time=$(echo "$avg_time_line" | awk -F': ' '{print $2}')
                
                local max_err_log=$(grep "Max Error" "$summary_file" | awk '{print $NF}')
                local avg_err_log=$(grep "Average Error" "$summary_file" | awk '{print $NF}')
                
                printf "| %-11s | %-8s | %-10s | %-9s | %-12s | %-16s | %-16s |\n" "$algo" "$ring_dim" "$mult_depth" "$scale_mod" "$avg_time" "$max_err_log" "$avg_err_log" >> "$final_summary_md"
            fi
        done
    done
    
    echo "" >> "$final_summary"
    echo "Note: Results are averaged over $NUM_TRIALS trials." >> "$final_summary"
    echo "=========================================================" >> "$final_summary"
    echo "" >> "$final_summary_md"
    echo "Note: Results are averaged over $NUM_TRIALS trials." >> "$final_summary_md"
    
    echo "Final summaries generated at:"
    echo "  - Text format: $final_summary"
    echo "  - Markdown format: $final_summary_md"
}

mkdir -p "${SCRIPT_DIR}/experimental_results/ours_hybrid/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/mehp24/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/ours/trials"
mkdir -p "${SCRIPT_DIR}/experimental_results/kway/trials"

> "${SCRIPT_DIR}/experimental_results/ours_hybrid/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/mehp24/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/ours/total_results.txt"
> "${SCRIPT_DIR}/experimental_results/kway/total_results.txt"

run_test "ours_hybrid" "DirectSortHTest" "${DIRECT_SIZES[@]}"
run_test "mehp24" "mehp24/Mehp24SortTest" "${MEHP24_SIZES[@]}"
run_test "ours" "DirectSortTest" "${DIRECT_SIZES[@]}"
run_test "kway" "k-way/KWaySort235Test" "${KWAY_SIZES[@]}"

generate_final_summary

echo "All experiments completed!"

# chmod +x run_experiments.sh
# ./run_experiments.s