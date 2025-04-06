#!/usr/bin/env python3
"""
SWC to DASP Category Mapper

This script analyzes the relationship between SWC (Smart Contract Weakness) IDs
and DASP (Decentralized Application Security Project) vulnerability categories.
It helps in understanding and validating the mapping used in vulnerability detection.

Usage:
    python swc_dasp_mapper.py
"""

import csv
import re
import json
from collections import defaultdict, Counter


def extract_swc_id(swc_id_string):
    """Extract the numeric part of SWC-ID from a string."""
    if not swc_id_string:
        return None
    
    # Try to extract a numeric ID
    match = re.search(r'SWC-(\d+)', swc_id_string)
    if match and match.group(1):
        return match.group(1)
    return None


def extract_filename(file_path):
    """Extract the filename from a file path."""
    if not file_path:
        return None
    return file_path.split('/')[-1]


def build_swc_dasp_mapping():
    """
    Build and return a mapping between SWC IDs and DASP categories
    based on known standards.
    """
    return {
        # Access Control related
        "105": "Access Control",  # Unprotected Ether Withdrawal
        "106": "Access Control",  # Unprotected SELFDESTRUCT Instruction
        "112": "Access Control",  # Delegatecall to Untrusted Callee
        "115": "Access Control",  # Authorization through tx.origin
        "118": "Access Control",  # Incorrect Constructor Name
        "124": "Access Control",  # Write to Arbitrary Storage Location
        "132": "Access Control",  # Unexpected Ether Balance
        
        # Arithmetic Issues
        "101": "Arithmetic Issues",  # Integer Overflow and Underflow
        "128": "Arithmetic Issues",  # DoS With Block Gas Limit
        
        # Bad Randomness
        "120": "Bad Randomness",  # Weak Sources of Randomness from Chain Attributes
        "136": "Bad Randomness",  # Unencrypted Private Data On-Chain
        
        # Denial of Service
        "128": "Denial of Service",  # DoS With Block Gas Limit
        "113": "Denial of Service",  # DoS with Failed Call
        
        # Front-Running
        "114": "Front-Running",  # Transaction Order Dependence
        
        # Reentrancy
        "107": "Reentrancy",  # Reentrancy
        
        # Time Manipulation
        "116": "Time Manipulation",  # Block values as a proxy for time
        "133": "Time Manipulation",  # Hash Collisions With Multiple Variable Length Arguments
        
        # Unchecked Return Values
        "104": "Unchecked Return Values",  # Unchecked Call Return Value
        "113": "Unchecked Return Values",  # DoS with Failed Call (can also be categorized as Unchecked Return)
    }


def build_swc_description_mapping():
    """
    Build and return a mapping between SWC IDs and their descriptions.
    """
    return {
        "100": "Function Default Visibility",
        "101": "Integer Overflow and Underflow",
        "102": "Outdated Compiler Version",
        "103": "Floating Pragma",
        "104": "Unchecked Call Return Value",
        "105": "Unprotected Ether Withdrawal",
        "106": "Unprotected SELFDESTRUCT Instruction",
        "107": "Reentrancy",
        "108": "State Variable Default Visibility",
        "109": "Uninitialized Storage Pointer",
        "110": "Assert Violation",
        "111": "Use of Deprecated Solidity Functions",
        "112": "Delegatecall to Untrusted Callee",
        "113": "DoS with Failed Call",
        "114": "Transaction Order Dependence",
        "115": "Authorization through tx.origin",
        "116": "Block values as a proxy for time",
        "117": "Signature Malleability",
        "118": "Incorrect Constructor Name",
        "119": "Shadowing State Variables",
        "120": "Weak Sources of Randomness from Chain Attributes",
        "121": "Missing Protection against Signature Replay Attacks",
        "122": "Lack of Proper Signature Verification",
        "123": "Requirement Violation",
        "124": "Write to Arbitrary Storage Location",
        "125": "Incorrect Inheritance Order",
        "126": "Insufficient Gas Griefing",
        "127": "Arbitrary Jump with Function Type Variable",
        "128": "DoS With Block Gas Limit",
        "129": "Typographical Error",
        "130": "Right-To-Left-Override control character",
        "131": "Presence of unused variables",
        "132": "Unexpected Ether Balance",
        "133": "Hash Collisions With Multiple Variable Length Arguments",
        "134": "Message call with hardcoded gas amount",
        "135": "Code With No Effects",
        "136": "Unencrypted Private Data On-Chain"
    }


def analyze_swc_distribution(output_files):
    """
    Analyze the distribution of SWC IDs across output files.
    
    Args:
        output_files: List of output CSV files to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    # Build reference mappings
    swc_to_dasp = build_swc_dasp_mapping()
    swc_to_description = build_swc_description_mapping()
    
    # Counters for analysis
    swc_counter = Counter()
    file_category_swc = defaultdict(lambda: defaultdict(Counter))
    swc_to_detected_dasp = defaultdict(Counter)
    
    # Process each output file
    for file_path in output_files:
        # Extract category from filename
        file_category = file_path.split('_')[-1].replace('.csv', '')
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'SWC-ID' in row and row['SWC-ID']:
                    swc_id = extract_swc_id(row['SWC-ID'])
                    if swc_id:
                        swc_counter[swc_id] += 1
                        file_category_swc[file_category][swc_id] += 1
                        
                        # Map to DASP category from filename
                        if file_category == 'access_control':
                            swc_to_detected_dasp[swc_id]['Access Control'] += 1
                        elif file_category == 'arithmetic':
                            swc_to_detected_dasp[swc_id]['Arithmetic Issues'] += 1
                        elif file_category == 'bad_randomness':
                            swc_to_detected_dasp[swc_id]['Bad Randomness'] += 1
                        elif file_category == 'denial_of_service':
                            swc_to_detected_dasp[swc_id]['Denial of Service'] += 1
                        elif file_category == 'front_running':
                            swc_to_detected_dasp[swc_id]['Front-Running'] += 1
                        elif file_category == 'reentrancy':
                            swc_to_detected_dasp[swc_id]['Reentrancy'] += 1
                        elif file_category == 'short_addresses':
                            swc_to_detected_dasp[swc_id]['Short Address/Parameter Attack'] += 1
                        elif file_category == 'time_manipulation':
                            swc_to_detected_dasp[swc_id]['Time Manipulation'] += 1
                        elif file_category == 'unchecked_low_level_calls':
                            swc_to_detected_dasp[swc_id]['Unchecked Return Values'] += 1
                        else:
                            swc_to_detected_dasp[swc_id]['Unknown Unknowns'] += 1
    
    # Analyze inconsistencies in mapping
    inconsistent_mappings = []
    for swc_id, dasp_counts in swc_to_detected_dasp.items():
        if len(dasp_counts) > 1:
            # This SWC ID is associated with multiple DASP categories
            most_common_dasp = dasp_counts.most_common(1)[0][0]
            reference_dasp = swc_to_dasp.get(swc_id, "Not defined")
            
            inconsistent_mappings.append({
                'swc_id': swc_id,
                'description': swc_to_description.get(swc_id, "Unknown"),
                'reference_dasp': reference_dasp,
                'detected_dasps': dict(dasp_counts),
                'most_common_dasp': most_common_dasp,
                'is_consistent_with_reference': reference_dasp == most_common_dasp
            })
    
    # Generate analysis results
    results = {
        'swc_distribution': dict(swc_counter),
        'file_category_swc_distribution': {k: dict(v) for k, v in file_category_swc.items()},
        'swc_to_detected_dasp': {k: dict(v) for k, v in swc_to_detected_dasp.items()},
        'inconsistent_mappings': inconsistent_mappings,
        'reference_swc_to_dasp': swc_to_dasp,
        'swc_to_description': swc_to_description
    }
    
    return results


def print_analysis_report(analysis):
    """
    Print a detailed report of the SWC to DASP mapping analysis.
    
    Args:
        analysis: Dictionary containing analysis results
    """
    print("\n" + "="*80)
    print(" "*20 + "SWC TO DASP CATEGORY MAPPING ANALYSIS")
    print("="*80)
    
    # Print overall SWC distribution
    print("\n1. OVERALL SWC ID DISTRIBUTION")
    print("-----------------------------")
    
    sorted_swcs = sorted(analysis['swc_distribution'].items(), 
                          key=lambda x: x[1], reverse=True)
    
    for swc_id, count in sorted_swcs[:10]:  # Show top 10
        desc = analysis['swc_to_description'].get(swc_id, "Unknown")
        ref_dasp = analysis['reference_swc_to_dasp'].get(swc_id, "Not defined")
        print(f"SWC-{swc_id}: {count} occurrences - {desc} (Ref: {ref_dasp})")
    
    if len(sorted_swcs) > 10:
        print(f"... and {len(sorted_swcs) - 10} more SWC IDs")
    
    # Print inconsistencies in mapping
    print("\n2. INCONSISTENT SWC TO DASP MAPPINGS")
    print("----------------------------------")
    
    if analysis['inconsistent_mappings']:
        for i, mapping in enumerate(analysis['inconsistent_mappings'], 1):
            print(f"\n{i}. SWC-{mapping['swc_id']}: {mapping['description']}")
            print(f"   Reference DASP: {mapping['reference_dasp']}")
            print(f"   Detected DASP categories:")
            
            for dasp, count in sorted(mapping['detected_dasps'].items(), 
                                      key=lambda x: x[1], reverse=True):
                print(f"    - {dasp}: {count} occurrences")
            
            if mapping['is_consistent_with_reference']:
                print(f"   ✓ Most common detection ({mapping['most_common_dasp']}) matches reference")
            else:
                print(f"   ✗ Most common detection ({mapping['most_common_dasp']}) differs from reference")
    else:
        print("No inconsistencies found in SWC to DASP mappings.")
    
    # Provide recommendations
    print("\n3. RECOMMENDATIONS")
    print("----------------")
    
    if analysis['inconsistent_mappings']:
        print("Based on the analysis, consider revising these SWC to DASP mappings:")
        
        for mapping in analysis['inconsistent_mappings']:
            if not mapping['is_consistent_with_reference']:
                most_common = mapping['most_common_dasp']
                reference = mapping['reference_dasp']
                print(f"- SWC-{mapping['swc_id']} ({mapping['description']}): "
                      f"Consider changing from '{reference}' to '{most_common}'")
    else:
        print("The current SWC to DASP mapping appears consistent with detections.")
    
    # Print DASP category coverage
    print("\n4. DASP CATEGORY COVERAGE")
    print("------------------------")
    
    # Count SWCs per DASP category in reference mapping
    dasp_coverage = defaultdict(list)
    for swc_id, dasp in analysis['reference_swc_to_dasp'].items():
        dasp_coverage[dasp].append(swc_id)
    
    for dasp, swc_ids in sorted(dasp_coverage.items()):
        print(f"{dasp}: {len(swc_ids)} SWC IDs")
        swc_desc = [f"SWC-{swc} ({analysis['swc_to_description'].get(swc, 'Unknown')})" 
                     for swc in swc_ids]
        print(f"  {', '.join(swc_desc)}")
    
    # Print missing DASP categories
    all_dasp = {
        "Access Control", "Arithmetic Issues", "Bad Randomness", 
        "Denial of Service", "Front-Running", "Reentrancy",
        "Short Address/Parameter Attack", "Time Manipulation", 
        "Unchecked Return Values", "Unknown Unknowns"
    }
    
    missing_dasp = all_dasp - set(dasp_coverage.keys())
    if missing_dasp:
        print("\nDASP categories without SWC mappings:")
        for dasp in missing_dasp:
            print(f"- {dasp}")
    
    print("\n" + "="*80)


def save_mapping_json(analysis, output_file='swc_dasp_mapping.json'):
    """
    Save the SWC to DASP mapping analysis as a JSON file.
    
    Args:
        analysis: Dictionary containing analysis results
        output_file: Path to save the JSON file
    """
    # Create a clean version of the mapping for export
    mapping_data = {
        'reference_mapping': analysis['reference_swc_to_dasp'],
        'swc_descriptions': analysis['swc_to_description'],
        'detected_mapping': {
            swc_id: max(dasps.items(), key=lambda x: x[1])[0]
            for swc_id, dasps in analysis['swc_to_detected_dasp'].items()
        },
        'inconsistencies': [
            {
                'swc_id': item['swc_id'],
                'description': item['description'],
                'reference_dasp': item['reference_dasp'],
                'most_common_detected': item['most_common_dasp'],
                'all_detected': item['detected_dasps']
            }
            for item in analysis['inconsistent_mappings']
        ]
    }
    
    # Add recommended mapping based on detection data
    mapping_data['recommended_mapping'] = {}
    for swc_id in analysis['swc_to_description'].keys():
        if swc_id in mapping_data['detected_mapping']:
            # Use detected mapping if available
            mapping_data['recommended_mapping'][swc_id] = mapping_data['detected_mapping'][swc_id]
        elif swc_id in analysis['reference_swc_to_dasp']:
            # Fall back to reference mapping
            mapping_data['recommended_mapping'][swc_id] = analysis['reference_swc_to_dasp'][swc_id]
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(mapping_data, f, indent=2)
    
    print(f"SWC to DASP mapping saved to {output_file}")


def main():
    """Main function to run the SWC to DASP mapping analysis."""
    output_files = [
        'output_access_control.csv',
        'output_arithmetic.csv',
        'output_bad_randomness.csv',
        'output_denial_of_service.csv',
        'output_front_running.csv',
        'output_other.csv',
        'output_reentrancy.csv',
        'output_short_addresses.csv',
        'output_time_manipulation.csv',
        'output_unchecked_low_level_calls.csv'
    ]
    
    # Check if files exist
    existing_files = [f for f in output_files if os.path.isfile(f)]
    
    if not existing_files:
        print("Error: No output files found")
        return
    
    print(f"Analyzing {len(existing_files)} output files...")
    analysis = analyze_swc_distribution(existing_files)
    
    print_analysis_report(analysis)
    save_mapping_json(analysis)


if __name__ == "__main__":
    import os
    main()
