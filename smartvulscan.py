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
from concurrent.futures import ProcessPoolExecutor

start_time = time.time()


def read_file_contents(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()
        return lines


def create_csv(output_filename, formatted_output, elapsed_time, other_content=None):
    with open('output.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        field = ['Tool', 'File', 'Contract', 'Vulnerability', 'Severity', 'SWC-ID', 'Remediation',
                 'Description/More Info', 'Execution time' , 'Total Time']

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


# def set_resource_limits():
#     # maximum CPU time to 30 minutes (1800 seconds)
#     resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
#
#     # maximum memory usage is 4 GB
#     resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024))
#
#     # maximum number of open file descriptors is 1024
#     resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))


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
            proc = subprocess.run(['slither', file_path, param_checklist, param_no_optimization, param_no_informational,param_no_low], stdout=f, stderr=f, text=True)
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
            proc = subprocess.run(['myth', 'analyze', params_execution_timeout, timeout, file_path], stdout=f, stderr=f, text=True)
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

        # print(issue['title'])
        # print(f"SWC ID: {issue['swc_id']}")
        # print(f"Severity: {issue['severity']}")
        # print(f"Contract: {issue['contract']}")
        # print(f"Function: {issue['function_name']}")
        # print(f"Description: {issue['description']}")
        # print(f"Gas Usage: {issue['gas_usage']}")
        # if 'code_lines' in issue:
        #     print("Code:")
        #     for line in issue['code_lines']:
        #         print(f"  {line}")
        # if 'initial_state' in issue:
        #     print("Initial State:")
        #     for line in issue['initial_state']:
        #         print(f"  {line}")
        # if 'transaction_sequence' in issue:
        #     print("Transaction Sequence:")
        #     for line in issue['transaction_sequence']:
        #         print(f"  {line}")
        # print()
        # # TODO make pattern more efficient
        # pattern = r"==== (.+?) ====\n(SWC ID: \d+\nSeverity: \w+\nContract: \w+\nFunction name: \w+\(\)?\n(?:PC address: \d+\n(?:Estimated Gas Usage: \d+ - \d+\n)?)?(.+?)\n--------------------\nIn file: (.+?)\n\n(.+?)\n\n--------------------)"
        # print("this is the output: \n")
        # print(output)
        # matches = re.findall(pattern, output, re.DOTALL)
        #
        # for match in matches:
        #     title, details, description, file_line, code = match
        #     # Extract SWC ID
        #     swc_id = re.search(r"SWC ID: (\d+)", details).group(1)
        #     print(f"SWC ID: {swc_id}")
        #     # Extract vulnerability severity
        #     severity = re.search(r"Severity: (\w+)", details).group(1)
        #
        #     # Extract contract name
        #     contract = re.search(r"Contract: (\w+)", details).group(1)
        #
        #     description = ""  #re.search(r"Estimated Gas Usage: (\d+ - \d+)", details).group(1)
        #
        #     remediation = re.search(r"(.+?)\n--------------------\n", details).group(1)
        if 'title'in issue:
            vulnerability = issue['title'].strip("=")
            vulnerability = {
                    "title": vulnerability.strip(),
                    # "description": description.strip(),
                    # "file_line": file_line.strip(),
                    # "code": code.strip(),
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


def format_results(s_output, file_name, tool_time):
    # Regex to extract useful info
    desc_regex = r"Reference: (.*)"
    sev_regex = r"INFO:Detectors:"
    # TODO: add regular expressions tailored to each security tool to extract the required vulnerability information
    # TODO: create parser for slither output when using markdown

    # Initialize output list of lists
    output = []
    swc_id = " "
    contract = " "
    # Loop through each result

    # new
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

        issue_name,  impact, confidence, details = issue
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

        output.append(
            ["slither", file_location, contract_name, issue_name, impact, "SWC-ID: https://swcregistry.io/docs/SWC-" + swc_id, confidence, "",
             tool_time])

        parsed_data["issues"].append(issue_data)

    # for result in s_output.split("INFO:Detectors:"):
    #     if not result.strip():
    #         continue
    #     lines = result.strip().split("\n")
    #     # Extract vulnerability name
    #     vuln = lines[0]
    #     # solc is not a vulnerability so exclude from the output
    #     if "'solc --version' running" == vuln:
    #         continue
    #     # Extract description
    #     desc_match = re.search(desc_regex, result)
    #     if desc_match:
    #         desc = desc_match.group(1)
    #     else:
    #         desc = "No description provided"
    #
    #     match = re.search(r'\s*(\w+)', vuln)
    #     if match and contract != "":
    #         if "Reentrancy" in result or "Pragma" in result:
    #             print("reentrancy")
    #         else:
    #             contract = match.group(1)
    #
    #     # Handle severity and specific remediations
    #     if "Reentrancy" in result:
    #         sev = "High"
    #         swc_id = "107"
    #         rem = "To avoid re-entrancy, you can use the Checks-Effects-Interactions pattern as outlined in https://docs.soliditylang.org/en/v0.4.21/security-considerations.html#re-entrancy"
    #     elif "'solc --version' running" in result:
    #         sev = "None"
    #         rem = "This is not a vulnerability"
    #     elif "integer overflow" in result:
    #         sev = "High"
    #         swc_id = "101"
    #         rem = "It is recommended to use vetted safe math libraries for arithmetic operations consistently throughout the smart contract system. Refer to https://swcregistry.io/docs/SWC-101/"
    #     elif "timestamp" in result:
    #         sev = "Low"
    #         swc_id = "116"
    #         rem = "Developers should write smart contracts with the notion that block values are not precise, and the use of them can lead to unexpected effects. Alterna-tively, they may make use of oracles. refer to https://swcregistry.io/docs/SWC-116/ "
    #     elif "locking ether" in result:
    #         sev = "Medium"
    #         swc_id = "132"
    #         rem = "Avoid strict equality checks for the Ether balance in a contract. Contracts can behave erroneously when they strictly assume a specific Ether balance. It is always possible to forcibly send ether to a contract (without triggering its fallback function), using selfdestruct, or by mining to the account. In the worst case scenario this could lead to DOS conditions that might render the contract unusa-ble. refer to https://swcregistry.io/docs/SWC-132/#lockdropsol "
    #     elif "old versions" in result:
    #         sev = "Medium"
    #         swc_id = "102"
    #         rem = "It is recommended to use a recent version of the Solidity compiler. Using an outdated compiler version can be problematic especially if there are publicly disclosed bugs and issues that affect the current compiler version. refer to https://swcregistry.io/docs/SWC-102/#version_0_4_13sol "
    #     elif "immutable" in result:
    #         sev = "High"
    #         rem = "Add the immutable attribute to state variables that never change or are set only in the constructor."
    #     elif "Low" in result:
    #         sev = "Low"
    #         rem = "See description"
    #     elif "Medium" in result:
    #         sev = "Medium"
    #         rem = "See description"
    #     else:
    #         # Default to generic remediation
    #         sev = "High"
    #         rem = "See description"
    #
    #     output.append(
    #         ["slither", file_name, contract, vuln, sev, "SWC-ID: https://swcregistry.io/docs/SWC-" + swc_id, rem, desc,
    #          tool_time])

    print(output)
    return output


def main():
    if len(sys.argv) < 2:
        logging.error("Usage: python smartvulscan.py <file_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        logging.error(f"Error: {file_path} does not exist")
        sys.exit(1)

    # Extract the base name of the smart contract file without the path
    contract_filename = get_file_name(file_path)

    # Construct the dynamic output file name based on the smart contract file
    dynamic_output_filename = f"{contract_filename}_output.csv"

    # Process the smart contract files (if needed)
    # result = process_files([file_path])

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

        # for contract in contract_files:
        #     slither_out = analyse_smart_contract_with_slither(contract)
        #     for out in slither_out:
        #         formatted_output.append(out)

        # with ProcessPoolExecutor() as process_pool:
        #     # for slither_output in process_pool.map(analyse_smart_contract_with_slither, contract_files):
        #     # submit tasks and collect futures
        #     futures = [process_pool.submit(analyse_smart_contract_with_slither, i) for i in contract_files]
        #     # process task results in the order they were submitted
        #     for future in futures:
        #         # retrieve the result
        #
        #         print(future.result())
        #         print(len(future.result()))
        #         if len(future.result()) > 0:
        #             items = future.result()
        #             for item in items:
        #                 formatted_output.append(item)
        #         else:
        #             formatted_output.append(future.result())



                # for slither_out in slither_output:
                #     formatted_output.append(slither_out)

        # with ProcessPoolExecutor() as process_pool:
        #     for mythril_output in process_pool.map(analyse_smart_contract_with_mythril, contract_files):
        #         if mythril_output is not None:
        #             print(mythril_output)
        #             for mythril_out in mythril_output:
        #                 if mythril_out is not None:
        #                     formatted_output.append(mythril_out)

        for cfile in contract_files:
            print("\n > analyzing file: " + cfile + "\n")
            slither_output = analyse_smart_contract_with_slither(cfile)
            for slither_out in slither_output:
                formatted_output.append(slither_out)
            # formatted_output.append(slither_output )
            mythril_output = analyse_smart_contract_with_mythril(cfile)
            for out in mythril_output:
                # print(out)
                formatted_output.append(out)


    else:
        print("\n > analyzing file: " + file_path + "\n")
        slither_output = analyse_smart_contract_with_slither(file_path)
        formatted_output = []
        for slither_out in slither_output:
            formatted_output.append(slither_out)

        mythril_output = analyse_smart_contract_with_mythril(file_path)
        for out in mythril_output:
            # print(out)
            formatted_output.append(out)

    elapsed_time = time.time() - start_time

    create_csv(dynamic_output_filename, formatted_output, elapsed_time)

    print(f"Smart Contract scanned successfully!.")
    print(f"Time taken: {elapsed_time} seconds")


def get_file_name(file_path):
    contract_filename = os.path.basename(file_path)
    return contract_filename


if __name__ == "__main__":
    main()
