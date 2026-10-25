#!/bin/bash
# HermesShield Benchmark - Reproducible Benchmark Command
# Usage: ./scripts/benchmark.sh [options]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
LAB_IMAGE="hermes-benchmark-lab:latest"
LAB_DIR="$(dirname "$0")/../lab"
OUTPUT_DIR="$(dirname "$0")/../results"
SKIP_BUILD=false
SKIP_CLEANUP=false
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --lab-image)
            LAB_IMAGE="$2"
            shift 2
            ;;
        --lab-dir)
            LAB_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-cleanup)
            SKIP_CLEANUP=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --lab-image IMAGE     Docker image name for lab (default: hermes-benchmark-lab:latest)"
            echo "  --lab-dir DIR         Path to lab directory (default: ../lab)"
            echo "  --output-dir DIR      Output directory for results (default: ../results)"
            echo "  --skip-build          Skip building the lab Docker image"
            echo "  --skip-cleanup        Don't stop lab container after benchmark"
            echo "  --verbose             Enable verbose output"
            echo "  -h, --help            Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Make paths absolute
LAB_DIR="$(realpath "$LAB_DIR")"
OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  HermesShield Benchmark Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Lab Image:     $LAB_IMAGE"
echo "Lab Directory: $LAB_DIR"
echo "Output Dir:    $OUTPUT_DIR"
echo "Skip Build:    $SKIP_BUILD"
echo "Skip Cleanup:  $SKIP_CLEANUP"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker not found${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found${NC}"
    exit 1
fi

if [[ ! -f "$LAB_DIR/vulnerabilities.json" ]]; then
    echo -e "${RED}Error: vulnerabilities.json not found in $LAB_DIR${NC}"
    exit 1
fi

if [[ ! -f "$LAB_DIR/Dockerfile" ]]; then
    echo -e "${RED}Error: Dockerfile not found in $LAB_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}Prerequisites OK${NC}"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build lab image
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo -e "${YELLOW}Building lab Docker image...${NC}"
    docker build -t "$LAB_IMAGE" "$LAB_DIR"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Failed to build lab image${NC}"
        exit 1
    fi
    echo -e "${GREEN}Lab image built successfully${NC}"
else
    echo -e "${YELLOW}Skipping lab image build${NC}"
fi

# Check if lab image exists
if ! docker image inspect "$LAB_IMAGE" &> /dev/null; then
    echo -e "${RED}Error: Lab image $LAB_IMAGE not found${NC}"
    exit 1
fi

# Run benchmark
echo -e "${YELLOW}Starting benchmark...${NC}"
echo ""

cd "$(dirname "$0")/.."
python3 run_benchmark.py \
    --lab-dir "$LAB_DIR" \
    --lab-image "$LAB_IMAGE" \
    --output-dir "$OUTPUT_DIR" \
    $([[ "$SKIP_BUILD" == "true" ]] && echo "--skip-build") \
    $([[ "$SKIP_CLEANUP" == "true" ]] && echo "--skip-cleanup") \
    $([[ "$VERBOSE" == "true" ]] && echo "--verbose")

BENCHMARK_EXIT_CODE=$?

echo ""
if [[ $BENCHMARK_EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Benchmark completed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Results saved to: $OUTPUT_DIR"
    ls -la "$OUTPUT_DIR"/*.json "$OUTPUT_DIR"/*.md 2>/dev/null | head -5
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  Benchmark failed with exit code $BENCHMARK_EXIT_CODE${NC}"
    echo -e "${RED}========================================${NC}"
fi

exit $BENCHMARK_EXIT_CODE