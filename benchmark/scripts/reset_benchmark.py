#!/usr/bin/env python3
"""
HermesShield Benchmark Reset Script

Resets the benchmark environment to a clean state.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: list, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return result."""
    try:
        return subprocess.run(cmd, capture_output=capture, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "timeout")


def reset_benchmark(lab_image: str = "hermes-benchmark-lab:latest",
                    container_name: str = "hermes-benchmark-lab",
                    clean_results: bool = False,
                    results_dir: str = "benchmark/results"):
    """Reset the benchmark environment."""
    
    print(f"Resetting benchmark environment...")
    print(f"  Lab image: {lab_image}")
    print(f"  Container: {container_name}")
    print(f"  Clean results: {clean_results}")
    print(f"  Results dir: {results_dir}")
    print()

    # Stop and remove container
    print("Stopping and removing container...")
    run_cmd(["docker", "stop", container_name], capture=False)
    run_cmd(["docker", "rm", container_name], capture=False)

    # Remove lab image
    print("Removing lab image...")
    run_cmd(["docker", "rmi", "-f", lab_image], capture=False)

    # Clean results directory
    if clean_results:
        results_path = Path(results_dir)
        if results_path.exists():
            import shutil
            print(f"Cleaning results directory: {results_path}")
            shutil.rmtree(results_path)
            results_path.mkdir(parents=True, exist_ok=True)
        else:
            print(f"Results directory not found: {results_path}")

    # Clean Docker system (optional)
    print("Cleaning Docker system...")
    run_cmd(["docker", "system", "prune", "-f"], capture=False)

    print()
    print("Benchmark reset complete!")
    print()
    print("To run benchmark again:")
    print("  cd benchmark")
    print("  python run_benchmark.py --lab-image hermes-benchmark-lab:latest")


def main():
    parser = argparse.ArgumentParser(description="Reset HermesShield Benchmark")
    parser.add_argument("--lab-image", default="hermes-benchmark-lab:latest",
                        help="Lab Docker image name")
    parser.add_argument("--container", default="hermes-benchmark-lab",
                        help="Container name")
    parser.add_argument("--clean-results", action="store_true",
                        help="Also clean results directory")
    parser.add_argument("--results-dir", default="benchmark/results",
                        help="Results directory path")
    
    args = parser.parse_args()
    
    reset_benchmark(
        lab_image=args.lab_image,
        container_name=args.container,
        clean_results=args.clean_results,
        results_dir=args.results_dir
    )


if __name__ == "__main__":
    main()