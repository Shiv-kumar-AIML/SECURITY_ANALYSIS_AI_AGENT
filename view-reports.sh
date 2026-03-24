#!/bin/bash
# Quick script to view security reports
# Usage: ./view-reports.sh [command]

set -e

COMMAND=${1:-list}

# Color codes
BOLD="\033[1m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"

echo -e "${BLUE}${BOLD}🔐 PENTAS Security Reporter${RESET}\n"

case "$COMMAND" in
    list)
        echo -e "${GREEN}📋 Listing all reports...${RESET}\n"
        python3 -m backend.cli list
        ;;
    show)
        echo -e "${GREEN}📖 Showing latest report...${RESET}\n"
        python3 -m backend.cli show
        ;;
    stats)
        echo -e "${GREEN}📊 Showing statistics...${RESET}\n"
        python3 -m backend.cli stats
        ;;
    compare)
        echo -e "${GREEN}🔄 Comparing last two scans...${RESET}\n"
        python3 -m backend.cli compare
        ;;
    *)
        echo -e "${BLUE}Usage:${RESET}"
        echo "  ./view-reports.sh list      - List all reports"
        echo "  ./view-reports.sh show      - Show latest report"
        echo "  ./view-reports.sh stats     - Show statistics"
        echo "  ./view-reports.sh compare   - Compare last two scans"
        echo ""
        echo "Or use directly:"
        echo "  python3 -m backend.cli [command]"
        ;;
esac
