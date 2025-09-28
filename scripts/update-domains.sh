#!/bin/bash

# Script to help maintain and update Kakao ad domains
# This can be expanded in the future to automatically detect new domains

set -e

FILTER_FILE="kakao-adblock-filter.txt"
TEMP_FILE="temp_filter.txt"

echo "Updating Kakao AdBlock Filter..."

# Function to add new domain if not already present
add_domain() {
    local domain="$1"
    local category="$2"

    if ! grep -q "||${domain}^" "$FILTER_FILE" 2>/dev/null; then
        echo "Adding new domain: $domain to category: $category"
        # This would need more sophisticated logic to add to correct section
        echo "||${domain}^" >> "$FILTER_FILE"
    else
        echo "Domain $domain already exists in filter"
    fi
}

# Function to validate filter syntax
validate_filter() {
    echo "Validating filter syntax..."

    # Count total rules
    local rule_count=$(grep -c '^||.*\^' "$FILTER_FILE" || echo "0")
    echo "Total blocking rules: $rule_count"

    # Check for duplicate rules
    local duplicates=$(grep '^||.*\^' "$FILTER_FILE" | sort | uniq -d | wc -l)
    if [ "$duplicates" -gt 0 ]; then
        echo "Warning: Found $duplicates duplicate rules"
        grep '^||.*\^' "$FILTER_FILE" | sort | uniq -d
    fi

    echo "Validation complete"
}

# Main execution
if [ "$1" = "validate" ]; then
    validate_filter
elif [ "$1" = "add" ] && [ -n "$2" ]; then
    add_domain "$2" "${3:-unknown}"
    validate_filter
else
    echo "Usage: $0 {validate|add <domain> [category]}"
    echo "Example: $0 add new.ad.kakao.com 'Kakao Core'"
    exit 1
fi