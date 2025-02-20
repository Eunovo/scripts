import matplotlib.pyplot as plt
import numpy as np
import re

# Function to extract benchmark data
def parse_benchmark_data(filename, batch_prefix, single_entry):
    number_of_items = []
    verification_times = []
    single_verification_time = None

    with open(filename, "r") as file:
        for line in file:
            # Match batch verification entries
            match = re.match(rf"{batch_prefix}_(\d+)\s*,\s*\d+\.\d+\s*,\s*(\d+\.\d+)\s*,", line)
            if match:
                number_of_items.append(int(match.group(1)))
                verification_times.append(float(match.group(2)))
            
            # Match single verification time
            match_single = re.match(rf"{single_entry}\s*,\s*\d+\.\d+\s*,\s*(\d+\.\d+)\s*,", line)
            if match_single:
                single_verification_time = float(match_single.group(1))

    return number_of_items, verification_times, single_verification_time

def calculate_speedup_percentage(batch_times, single_time, number_of_items):
    """Calculate speedup percentage compared to sequential verification"""
    sequential_times = [single_time * t for t in number_of_items]
    batch_times = [batch_time * t for batch_time, t in zip(batch_times, number_of_items)]
    return [((seq - batch) / seq) * 100 for seq, batch in zip(sequential_times, batch_times)]

# Function to plot and save the graph
def plot_and_save(number_of_items, batch_times, single_time, xvalue, title, output_file):
    plt.figure(figsize=(10, 6))

    # Calculate speedup percentage
    speedup = calculate_speedup_percentage(batch_times, single_time, number_of_items)
    
    # Calculate highest and average speedup
    max_speedup = max(speedup)

    # Create the scatter plot
    plt.scatter(number_of_items, speedup, marker='o')

    # Indicate max speedup
    plt.axhline(y=max_speedup, color='red', linestyle='--', alpha=0.5)
    plt.text(min(number_of_items), max_speedup, f'Max speedup: {max_speedup:.1f}%', verticalalignment='bottom')

    # Labels and title
    plt.xscale('log')
    plt.xlabel(f"Number of {xvalue} (logarithmic)")
    plt.ylabel("Speedup Percentage (%)")
    plt.title(title)
    plt.grid(True, which="major", linestyle="--", linewidth=0.5)

    # Adjust layout to prevent text cutoff
    # plt.tight_layout()
    
    # Save the graph to file
    plt.savefig(output_file, dpi=300)
    print(f"Graph saved as {output_file}")

if __name__ == "__main__":
  # Process Schnorr signature verification data
  filename = "visualization/bench_output.txt"
  sig_number_of_items, sig_batch_times, sig_single_time = parse_benchmark_data(filename, 
                                                                          "schnorrsig_batch_verify", 
                                                                          "schnorrsig_verify")

  # Process Taproot tweak verification data
  tweak_number_of_items, tweak_batch_times, tweak_single_time = parse_benchmark_data(filename, 
                                                                                "tweak_check_batch_verify", 
                                                                                "tweak_add_check")

  # Generate graphs with updated titles
  plot_and_save(sig_number_of_items, sig_batch_times, sig_single_time, "signatures",
                "Schnorr Signature Batch Verification Speedup", 
                "visualization/batch_verification_speedup_plot.png")

  plot_and_save(tweak_number_of_items, tweak_batch_times, tweak_single_time, "tweak checks",
                "Taproot Tweak Batch Verification Speedup", 
                "visualization/tweak_verification_speedup_plot.png")

