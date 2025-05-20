"""
 LightCROSS: Lightweight Vulnerability cross-tool detector for smart contracts
 Author: Minaro Ikegima
 Adapted: Ioannis Sfyrakis
 Copyright Teesside University 2024
"""
import csv
import resource
import subprocess
import sys
import os
import logging
import json
import tempfile
import re
import time
import argparse
from concurrent.futures import ProcessPoolExecutor


def read_file_contents(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()
        return lines


def create_csv(output_filename, formatted_output, elapsed_time, other_content=None):
    with open('output.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        field = ['Tool', 'File', 'Contract', 'Vulnerability', 'Severity', 'SWC-ID', 'Remediation',
                 'Description/More Info', 'Execution time', 'Total Time']

        writer.writerow(field)
        for row in formatted_output:
            row.append(elapsed_time)
            writer.writerow(row)


def process_files(file_paths):
    result = ""
    for file_name in file_paths:
        lines = read_file_contents(file_name)
        result += f"{file_name}: {len(lines)} lines\n"

    return result


def set_resource_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024))


def analyse_smart_contract_with_slither(file_path):
    # params for creating a markdown list of issues with the smart contract
    param_checklist = "--checklist"
    param_no_optimization = "--exclude-optimization"
    param_no_informational = "--exclude-informational"
    param_no_low = "--exclude-low"
    try:
        with open('syslog-slither.txt', 'w') as f:
            print(file_path)
            start_time_slither = time.time()
            proc = subprocess.run(
                ['slither', file_path, param_checklist, param_no_optimization, param_no_informational, param_no_low],
                stdout=f, stderr=f, text=True)
            elapsed_time_slither = time.time() - start_time_slither
        with open("syslog-slither.txt") as f:
            f.seek(0)
            s_output = f.read()
            results = format_results(s_output, file_path, elapsed_time_slither)
            return results

    except subprocess.CalledProcessError as e:
        print("Slither analysis failed.")
        print(f"Command failed with error {e.returncode}, output: {e.output}")
        sys.exit(1)


def analyse_smart_contract_with_mythril(file_path):
    print("myth analyze: " + file_path + "\n")
    # TODO add parameter execution timeout for mythril added from command line
    timeout = "2000"
    params_execution_timeout = "--execution-timeout"

    try:
        with open('syslog-mythril.txt', 'w') as f:
            start_time_mythril = time.time()
            proc = subprocess.run(['myth', 'analyze', params_execution_timeout, timeout, file_path], stdout=f, stderr=f,
                                  text=True)
            elapsed_time_mythril = time.time() - start_time_mythril
        with open("syslog-mythril.txt") as f:
            f.seek(0)
            s_output = f.read()
            results_mythril = parse_mythril_output(s_output, file_path, elapsed_time_mythril)
            return results_mythril

    except subprocess.CalledProcessError as e:
        print("Mythril analysis failed.")
        print(f"Command failed with error {e.returncode}, output: {e.output}")
        sys.exit(1)


def parse_mythril_output_int(output):
    print(output)
    issues = []
    current_issue = {}
    code_lines = []
    initial_state = []
    transaction_sequence = []
    if output == 'The analysis was completed successfully. No issues were detected.':
        current_issue = {'title': 'The analysis was completed successfully. No issues were detected.',
                         'details': "",
                         'swc_id': "",
                         'severity': "",
                         'contract': "",
                         'function_name': "",
                         'pc_address': "",
                         'gas_usage': "",
                         'file_path': "",
                         'description': ""}
    else:
        for line in output.split('\n'):
            if line.startswith('==== '):
                if current_issue:
                    issues.append(current_issue)
                current_issue = {
                    'title': line.strip(),
                    'details': []
                }
            elif line.startswith('SWC ID:'):
                swc_id = line.split(':')[1].strip()
                current_issue['swc_id'] = swc_id
            elif line.startswith('Severity:'):
                severity = line.split(':')[1].strip()
                current_issue['severity'] = severity
            elif line.startswith('Contract:'):
                contract = line.split(':')[1].strip()
                current_issue['contract'] = contract
            elif line.startswith('Function name:'):
                function_name = line.split(':')[1].strip()
                current_issue['function_name'] = function_name
            elif line.startswith('PC address:'):
                pc_address = line.split(':')[1].strip()
                current_issue['pc_address'] = pc_address
            elif line.startswith('Estimated Gas Usage:'):
                gas_usage = line.split(':')[1].strip()
                current_issue['gas_usage'] = gas_usage
            elif line.startswith('--------------------'):
                pass
            elif line.startswith('In file:'):
                file_path = line.split(':')[1].strip()
                current_issue['file_path'] = file_path
                code_lines = []
            elif line.startswith('Initial State:'):
                initial_state = []
            elif line.startswith('Transaction Sequence:'):
                transaction_sequence = []
            else:
                if current_issue and 'description' not in current_issue:
                    current_issue['description'] = line.strip()
                elif current_issue and 'code_lines' in current_issue:
                    code_lines.append(line.strip())
                elif current_issue and 'initial_state' in current_issue:
                    initial_state.append(line.strip())
                elif current_issue and 'transaction_sequence' in current_issue:
                    transaction_sequence.append(line.strip())

            if code_lines:
                current_issue['code_lines'] = code_lines
            if initial_state:
                current_issue['initial_state'] = initial_state
            if transaction_sequence:
                current_issue['transaction_sequence'] = transaction_sequence

    if current_issue:
        issues.append(current_issue)
    return issues


def parse_mythril_output(output, file_name, tool_time):
    vulnerabilities = []
    issues = parse_mythril_output_int(output)
    print(len(issues))
    for issue in issues:
        print(issue)

        if 'title' in issue:
            vulnerability = issue['title'].strip("=")
            vulnerability = {
                "title": vulnerability.strip(),
                "swc_id": issue['swc_id'],
                "severity": issue['severity'],
                "contract": issue['contract'],
                "remediation": issue['description'],
                "description": "Estimated Gas Usage: " + issue['gas_usage'],
                "tool_time": tool_time
            }

            # TODO: fix the order of the columns for the mithril tool output
            vulnerabilities.append(
                ["mythril", file_name,
                 vulnerability['contract'], vulnerability['title'],
                 vulnerability['severity'],
                 "SWC-ID: https://swcregistry.io/docs/SWC-" + vulnerability['swc_id'],
                 vulnerability['remediation'],
                 vulnerability['description'], vulnerability['tool_time']
                 ])

    return vulnerabilities


def map_slither_to_swc(issue_name):
    slither_to_swc = {
        # High severity
        "arbitrary-send-eth": "105",  # SWC-105: Unprotected Ether Withdrawal
        "controlled-delegatecall": "112",  # SWC-112: Delegatecall to Untrusted Callee
        "tx-origin": "115",  # SWC-115: Authorization through tx.origin
        "controlled-array-length": "124",  # SWC-124: Write to Arbitrary Storage Location
        "reentrancy-eth": "107",  # SWC-107: Reentrancy
        "reentrancy-no-eth": "107",  # SWC-107: Reentrancy
        "uninitialized-state": "109",  # SWC-109: Uninitialized Storage Pointer
        "uninitialized-storage": "109",  # SWC-109: Uninitialized Storage Pointer

        # Medium severity
        "divide-before-multiply": "101",  # SWC-101: Integer Overflow and Underflow
        "unchecked-send": "104",  # SWC-104: Unchecked Call Return Value
        "unchecked-lowlevel": "104",  # SWC-104: Unchecked Call Return Value
        "unchecked-transfer": "104",  # SWC-104: Unchecked Call Return Value
        "unused-return": "104",  # SWC-104: Unchecked Call Return Value
        "locked-ether": "132",  # SWC-132: Unexpected Ether Balance
        "tautology": "135",  # SWC-135: Code With No Effects
        "weak-prng": "120",  # SWC-120: Weak Sources of Randomness
        "encode-packed-collision": "133",  # SWC-133: Hash Collisions With Multiple Variable Length Arguments

        # Low severity
        "constant-function-asm": "127",  # SWC-127: Arbitrary Jump with Function Type Variable
        "erc20-interface": "129",  # SWC-129: Typographical Error
        "incorrect-equality": "132",  # SWC-132: Unexpected Behavior
        "shadowing-state": "119",  # SWC-119: Shadowing State Variables
    }

    return slither_to_swc.get(issue_name, "Unknown")


def format_results(s_output, file_name, tool_time):
    # Initialize output list of lists
    output = []
    swc_id = " "
    contract = " "
    print("output for file: " + file_name +  "\n")
    print(s_output)

    # Extract summary
    pre_summary = re.findall(r'Summary([\s\S]*?)##', s_output)
    if len(pre_summary) > 0:
        summary = pre_summary[0].strip()
    else:
        summary = ""
    # Extract issues
    issues = re.findall(r'## (.+?)\nImpact: (.+?)\nConfidence: (.+?)\n([\s\S]*?)(?=\n\n|$)', s_output)

    parsed_data = {
        "summary": summary,
        "issues": []
    }

    for issue in issues:
        issue_name, impact, confidence, details = issue
        print("issue Name: " + issue_name)
        # Extract IDs and their details
        ids = re.findall(r'- \[ \] (ID-\d+)\n([\s\S]*?)(?=\n\n|$)', details)

        issue_data = {
            "name": issue_name,
            "impact": impact,
            "confidence": confidence,
            "swc_id": swc_id,
            "ids": []
        }

        contract_info = []

        for id_info in ids:
            id_num, id_details = id_info
            contract_info = re.search(r'\[(.*?)\]\((.*?)\)', id_details)
            if contract_info:
                contract_name, file_location = contract_info.groups()
            else:
                contract_name, file_location = "Unknown", "Unknown"

            issue_description = re.search(r'\) (.*?):\n', id_details)
            if issue_description:
                description = issue_description.group(1)
            else:
                description = "No description available"

            issue_data["ids"].append({
                "id": id_num,
                "contract": contract_name,
                "location": file_location,
                "description": description
            })

            swc_id = map_slither_to_swc(issue_name)

        output.append(
            ["slither", file_location, contract_name, issue_name, impact,
             "SWC-ID: https://swcregistry.io/docs/SWC-" + swc_id, confidence, "",
             tool_time])

        parsed_data["issues"].append(issue_data)

    print(output)
    return output


def get_file_name(file_path):
    contract_filename = os.path.basename(file_path)
    return contract_filename


def main():
    parser = argparse.ArgumentParser(
        description='LightCROSS: Lightweight Vulnerability cross-tool detector for smart contracts')
    parser.add_argument('file_path', help='Path to Solidity file or directory containing Solidity files')
    parser.add_argument('--tools', choices=['slither', 'mythril', 'both'], default='both',
                        help='Specify which analysis tools to run: slither, mythril, or both (default)')

    args = parser.parse_args()

    file_path = args.file_path
    selected_tools = args.tools

    if not os.path.exists(file_path):
        logging.error(f"Error: {file_path} does not exist")
        sys.exit(1)

    start_time = time.time()

    # Extract the base name of the smart contract file without the path
    contract_filename = get_file_name(file_path)

    # Construct the dynamic output file name based on the smart contract file
    dynamic_output_filename = f"{contract_filename}_output.csv"

    banner_content = (
        "=========================================================\n"
        "   LightCross: Solidity Smart Contract Cross-Tool Vulnerability Detector \n"
        "=========================================================\n\n"
    )
    contract_files = []

    # if the path is a folder
    if os.path.isdir(file_path):
        for root, dirs, files in os.walk(file_path):
            for file in files:
                if file.endswith('.sol'):
                    print(os.path.join(root, file) + "\n")
                    contract_files.append(os.path.join(root, file))

        formatted_output = []

        for cfile in contract_files:
            print(f"\n > analyzing file: {cfile}\n")

            # Run Slither if selected
            if selected_tools in ['slither', 'both']:
                print(f"Running Slither analysis on {cfile}")
                slither_output = analyse_smart_contract_with_slither(cfile)
                for slither_out in slither_output:
                    formatted_output.append(slither_out)

            # Run Mythril if selected
            if selected_tools in ['mythril', 'both']:
                print(f"Running Mythril analysis on {cfile}")
                mythril_output = analyse_smart_contract_with_mythril(cfile)
                for out in mythril_output:
                    formatted_output.append(out)

    else:
        print(f"\n > analyzing file: {file_path}\n")
        formatted_output = []

        if selected_tools in ['slither', 'both']:
            print(f"Running Slither analysis on {file_path}")
            slither_output = analyse_smart_contract_with_slither(file_path)
            for slither_out in slither_output:
                formatted_output.append(slither_out)

        if selected_tools in ['mythril', 'both']:
            print(f"Running Mythril analysis on {file_path}")
            mythril_output = analyse_smart_contract_with_mythril(file_path)
            for out in mythril_output:
                formatted_output.append(out)

    elapsed_time = time.time() - start_time

    create_csv(dynamic_output_filename, formatted_output, elapsed_time)

    tools_used = selected_tools if selected_tools != 'both' else 'Slither and Mythril'
    print(f"Smart Contract scanned successfully using {tools_used}!")
    print(f"Time taken: {elapsed_time} seconds")


def create_swc_dasp_mapping():
    """
    Creates a mapping from Smart Contract Weakness Classification (SWC)
    IDs to Decentralized Application Security Project (DASP) categories.

    Returns:
        dict: A dictionary with SWC IDs as keys and DASP categories as values.
    """

    DASP_CATEGORIES = {
        1: "Reentrancy",
        2: "Access Control",
        3: "Arithmetic Issues",
        4: "Unchecked Return Values",
        5: "Denial of Service",
        6: "Bad Randomness",
        7: "Front-Running",
        8: "Time Manipulation",
        9: "Short Address/Parameter Attack",
        10: "Unknown Unknowns"
    }

    # Create mapping from SWC IDs to DASP categories
    swc_to_dasp = {
        # DASP-1: Reentrancy
        "SWC-107": 1,  # Reentrancy

        # DASP-2: Access Control
        "SWC-105": 2,  # Unprotected Ether Withdrawal
        "SWC-106": 2,  # Unprotected SELFDESTRUCT Instruction
        "SWC-115": 2,  # Authorization through tx.origin
        "SWC-118": 2,  # Incorrect Constructor Name
        "SWC-123": 2,  # Requirement Violation
        "SWC-124": 2,  # Write to Arbitrary Storage Location
        "SWC-125": 2,  # Incorrect Inheritance Order
        "SWC-132": 2,  # Unexpected Ether Balance

        # DASP-3: Arithmetic Issues
        "SWC-101": 3,  # Integer Overflow and Underflow
        "SWC-128": 3,  # DoS With Block Gas Limit (has arithmetic aspects)
        "SWC-129": 3,  # Typographical Error (related to arithmetic)
        "SWC-130": 3,  # Right-To-Left-Override control character
        "SWC-131": 3,  # Presence of unused variables

        # DASP-4: Unchecked Return Values
        "SWC-104": 4,  # Unchecked Call Return Value
        "SWC-113": 4,  # DoS with Failed Call (related to unchecked returns)

        # DASP-5: Denial of Service
        "SWC-113": 5,  # DoS with Failed Call (also relevant to DASP-4)
        "SWC-114": 5,  # Transaction Order Dependence
        "SWC-128": 5,  # DoS With Block Gas Limit
        "SWC-129": 5,  # Typographical Error (can cause DoS)
        "SWC-133": 5,  # Hash Collisions With Multiple Variable Length Arguments
        "SWC-135": 5,  # Code With No Effects
        "SWC-138": 5,  # Unrestricted Low-Level Calls

        # DASP-6: Bad Randomness
        "SWC-116": 6,  # Block values as a proxy for time
        "SWC-120": 6,  # Weak Sources of Randomness from Chain Attributes

        # DASP-7: Front-Running
        "SWC-114": 7,  # Transaction Order Dependence (also relevant to DASP-5)
        "SWC-127": 7,  # Timestamp Dependence (can enable front-running)

        # DASP-8: Time Manipulation
        "SWC-116": 8,  # Block values as a proxy for time (also in DASP-6)
        "SWC-127": 8,  # Timestamp Dependence

        # DASP-9: Short Address/Parameter Attack
        "SWC-133": 9,  # Hash Collisions With Multiple Variable Length Arguments

        # DASP-10: Unknown Unknowns (miscellaneous)
        "SWC-100": 10,  # Function Default Visibility
        "SWC-102": 10,  # Outdated Compiler Version
        "SWC-103": 10,  # Floating Pragma
        "SWC-108": 10,  # State Variable Default Visibility
        "SWC-109": 10,  # Uninitialized Storage Pointer
        "SWC-110": 10,  # Assert Violation
        "SWC-111": 10,  # Use of Deprecated Functions
        "SWC-112": 10,  # Delegatecall to Untrusted Callee
        "SWC-117": 10,  # Signature Malleability
        "SWC-119": 10,  # Shadowing State Variables
        "SWC-121": 10,  # Missing Protection against Signature Replay Attacks
        "SWC-122": 10,  # Lack of Proper Signature Verification
        "SWC-126": 10,  # Insufficient Gas Griefing
        "SWC-134": 10,  # Message call with hardcoded gas amount
        "SWC-136": 10,  # Unencrypted Private Data On-Chain
        "SWC-137": 10,  # Signature Malleability
    }

    swc_to_dasp_details = {
        swc_id: {
            "dasp_id": dasp_id,
            "dasp_category": DASP_CATEGORIES[dasp_id]
        }
        for swc_id, dasp_id in swc_to_dasp.items()
    }

    return swc_to_dasp_details


def get_swcs_by_dasp_category(dasp_id):
    """
    Retrieves all SWC IDs associated with a specific DASP category.

    Args:
        dasp_id (int): The DASP category ID (1-10)

    Returns:
        list: List of SWC IDs that fall under the specified DASP category
    """
    mapping = create_swc_dasp_mapping()
    return [swc_id for swc_id, details in mapping.items() if details["dasp_id"] == dasp_id]


def get_dasp_from_swc(swc_id):
    """
    Get the DASP category for a specific SWC ID.

    Args:
        swc_id (str): The SWC ID (e.g., "SWC-107" or just "107")

    Returns:
        dict: Information about the DASP category or None if not found
    """
    if not swc_id.startswith("SWC-"):
        swc_id = f"SWC-{swc_id}"

    mapping = create_swc_dasp_mapping()
    if swc_id in mapping:
        return {
            "swc_id": swc_id,
            "dasp_id": mapping[swc_id]["dasp_id"],
            "dasp_category": mapping[swc_id]["dasp_category"]
        }
    return None


if __name__ == "__main__":
    swc_dasp_mapping = create_swc_dasp_mapping()

    print("Complete SWC to DASP Mapping:")
    for swc_id, details in swc_dasp_mapping.items():
        print(f"{swc_id}: DASP-{details['dasp_id']} ({details['dasp_category']})")

    print("\n")

    dasp2_swcs = get_swcs_by_dasp_category(2)
    print(f"SWCs in DASP-2 (Access Control): {', '.join(dasp2_swcs)}")

    dasp5_swcs = get_swcs_by_dasp_category(5)
    print(f"SWCs in DASP-5 (Denial of Service): {', '.join(dasp5_swcs)}")

if __name__ == "__main__":
    main()