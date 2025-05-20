#!/usr/bin/env python3
"""
This script analyzes vulnerability detection results by Mythril and Slither and by smart contract file.
It now includes integration with the SmartBugs raw dataset.

Usage:
    python tool_contract_breakdown.py
"""

import csv
from collections import defaultdict
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

from swc_dasp_mapper import build_swc_dasp_mapping, build_swc_description_mapping
from vulnerability_metrics import extract_swc_id, extract_filename, determine_dasp_category, clean_file_path, \
    slither_detector_to_swc

matplotlib.use('Agg')
import matplotlib.pyplot as plt

TOOL_VULNERABILITY_MAP = {
    'confuzzius': {
        'Arbitrary_Memory_Access': 'Access Control',
        'Leaking_Ether': 'Access Control',
        'Transaction_Order_Dependency': 'Front-Running',
        'Reentrancy': 'REENTRANCY',
        'Integer_Overflow': 'Arithmetic Issues',
        'Integer_Underflow': 'Arithmetic Issues',
        'Arithmetic': 'Arithmetic Issues',
        'Denial_of_Service': 'Denial of Service',
        'Unchecked_Call': 'Unchecked Return Values',
        'TimeStamp_Dependency': 'Time Manipulation',
        'Block_Dependency': 'Time Manipulation',
        'Unsafe_Delegatecall': 'Unchecked Return Values',
        'Unhandled_Exception': 'Unchecked Return Values',
        'Unprotected_Selfdestruct' : 'Access Control'
    },

    'conkas': {
        'Reentrancy': 'REENTRANCY',
        'Integer_Overflow': 'Arithmetic Issues',
        'Integer_Underflow': 'Arithmetic Issues',
        'Unchecked_Low_Level_Call': 'Unchecked Return Values',
        'Time_Manipulation': 'Time Manipulation',
        'Transaction_Ordering_Dependence': 'Front-Running'
    },

    'honeybadger': {
        'straw_man_contract': 'REENTRANCY',
        'Straw_man_contract': 'REENTRANCY',
        'uninitialised_struct': 'Unknown Unknowns',
        'hidden_transfer': 'Unknown Unknowns',
        'hidden_state_update': 'ignore',
        'inheritance_disorder': 'ignore',
        'balance_disorder': 'ignore',
        'type_overflow': 'Arithmetic Issues'
    },

    'maian': {
        'is_prodigal_vulnerable': 'Access Control',
        'is_suicidal_vulnerable': 'Access Control',
        'Ether_lock': 'Access Control',
        'Ether_leak_verified': 'Access Control',
        'is_lock_vulnerable': 'Unknown Unknowns',
        'No_Ether_leak_no_send': 'ignore',
        'No_Ether_lock_Ether_refused': 'ignore',
        'Not_destructible_no_self_destruct': 'ignore'
    },

    'manticore': {
        'Delegatecall to user controlled address': 'Access Control',
        'Delegatecall to user controlled function': 'Access Control',
        'Potential reentrancy vulnerability': 'REENTRANCY',
        'Reachable ether leak to sender': 'Access Control',
        'Reachable ether leak to sender via argument': 'Access Control',
        'Reachable external call to sender': 'Access Control',
        'Reachable external call to sender via argument': 'Access Control',
        'Reachable SELFDESTRUCT': 'Access Control',
        'Reentrancy multi-million ether bug': 'REENTRANCY',
        'Returned value at CALL instruction is not used': 'Unchecked Return Values',
        'Unsigned integer overflow at ADD instruction': 'Arithmetic Issues',
        'Unsigned integer overflow at MUL instruction': 'Arithmetic Issues',
        'Unsigned integer overflow at SUB instruction': 'Arithmetic Issues',
        'Warning ORIGIN instruction used': 'Access Control',
        'Warning TIMESTAMP instruction used': 'Time Manipulation',
        'INVALID instruction': 'Unknown Unknowns',
        'Potentially reading uninitialized memory at instruction': 'Unknown Unknowns',
        'Potentially reading uninitialized storage': 'Unknown Unknowns',
        'Warning BLOCKHASH instruction used': 'Unknown Unknowns',
        'Warning NUMBER instruction used': 'Unknown Unknowns'
    },

    'mythril': {
        'Call data forwarded with delegatecall()': 'Access Control',
        'DELEGATECALL to a user-supplied address': 'Access Control',
        'Delegatecall_to_user_supplied_address_SWC_112': 'Access Control',
        'Write_to_an_arbitrary_storage_location_SWC_124': 'Access Control',
        # 'Transaction_Order_Dependence_SWC_114': 'Access Control',
        'Ether send': 'Access Control',
        'Unchecked SUICIDE': 'Access Control',
        'Use of tx.origin': 'Access Control',
        'Unprotected_Ether_Withdrawal_SWC_105': 'Access Control',
        'Dependence_on_tx_origin_SWC_115': 'Access Control',

        # 'Message call to external contract': 'REENTRANCY',
        # 'State change after external call': 'REENTRANCY',
        'State access after external call': 'REENTRANCY',
        'External_Call_To_User_Supplied_Address_SWC_107': 'REENTRANCY',
        'State_access_after_external_call_SWC_107': 'REENTRANCY',

        'Integer Overflow': 'Arithmetic Issues',
        'Integer Underflow': 'Arithmetic Issues',
        'Integer_Arithmetic_Bugs_SWC_101': 'Arithmetic Issues',

        'Transaction order dependence': 'Front-Running',
        'Transaction_Order_Dependence_SWC_114': 'Front-Running',

        'Unchecked CALL return value': 'Unchecked Return Values',
        'Unchecked_return_value_from_external_call_SWC_104': 'Unchecked Return Values',
        'Unchecked return value from external call.': 'Unchecked Return Values',
        'Unchecked return value from external call': 'Unchecked Return Values',

        'Dependence_on_predictable_environment_variable_SWC_116': 'Time Manipulation',

        'Dependence_on_predictable_environment_variable_SWC_120': 'Bad Randomness',

        'Dependence on predictable environment variable': 'Unknown Unknowns',
        'Dependence on predictable variable': 'Unknown Unknowns',
        'Exception state': 'Unknown Unknowns',
        'Exception_State_SWC_110': 'Unknown Unknowns',

        'Multiple Calls': 'ignore',
        'Multiple_Calls_in_a_Single_Transaction_SWC_113': 'Denial of Service'
    },

    'osiris': {
        'callstack_bug': 'Denial of Service',
        'concurrency_bug': 'ignore',
        'division_bugs': 'Arithmetic Issues',
        'Division_bugs': 'Arithmetic Issues',
        'overflow_bugs': 'Arithmetic Issues',
        'reentrancy_bug': 'REENTRANCY',
        'signedness_bugs': 'Arithmetic Issues',
        'time_dependency_bug': 'Time Manipulation',
        'Time_dependency_bug': 'Time Manipulation',
        'truncation_bugs': 'Arithmetic Issues',
        'Overflow_bugs': 'Arithmetic Issues',
        'Underflow_bugs': 'Arithmetic Issues',
        'Truncation_bugs': 'Arithmetic Issues',
        'Reentrancy_bug': 'REENTRANCY',
        'Concurrency_bug': 'Front Running',
        'Callstack_bug': 'Unchecked Return Values',
        'underflow_bugs': 'Arithmetic Issues'
    },

    'oyente': {
        'Re-Entrancy Vulnerability.': 'REENTRANCY',
        'Re_Entrancy_Vulnerability': 'REENTRANCY',
        'Integer Overflow': 'Arithmetic Issues',
        'Integer Underflow': 'Arithmetic Issues',
        'Callstack Depth Attack Vulnerability.': 'Denial of Service',
        'Timestamp Dependency': 'Time Manipulation',
        'Timestamp_Dependency': 'Time Manipulation',
        'Integer_Overflow': 'Arithmetic Issues',
        'Integer_Underflow': 'Arithmetic Issues',
        'Transaction_Ordering_Dependence_TOD': 'Front Running',
        'Callstack_Depth_Attack_Vulnerability': 'Unchecked Return Values',
        'Parity Multisig Bug 2.': 'Access Control'
    },

    'securify': {
        'DAO': 'REENTRANCY',
        'DAOConstantGas': 'REENTRANCY',
        'UnhandledException': 'Unchecked Return Values',
        'TODAmount': 'Front-Running',
        'TODReceiver': 'Front-Running',
        'TODTransfer': 'Front-Running',
        'UnrestrictedEtherFlow': 'Access Control',
        'UnrestrictedWrite': 'Access Control',
        'LockedEther': 'Unknown Unknowns',
        'MissingInputValidation': 'ignore',
        'RepeatedCall': 'ignore'
    },

    'sfuzz': {
        'Reentrancy': 'REENTRANCY',
        'Integer_Overflow': 'Arithmetic Issues',
        'Integer_Underflow': 'Arithmetic Issues',
        'Dangerous_Delegate_Call': 'Unchecked Return Values',
        'Timestamp_Dependency': 'Time Manipulation',
        'Block_Number_Dependency': 'Time Manipulation',
        'Exception_Disorder': 'Unchecked Return Values',
        'Gasless_Send': 'Unchecked Return Values'
    },

    'slither': {
        'arbitrary_send': 'Access Control',
        'arbitrary-send': 'Access Control',
        'arbitrary_send_eth': 'Access Control',
        'arbitrary-send-eth': 'Access Control',
        'controlled-delegatecall': 'Access Control',
        'controlled_delegatecall': 'Access Control',
        'incorrect_modifier': 'Access Control',
        'suicidal': 'Access Control',
        'tx-origin': 'Access Control',
        'tx_origin': 'Access Control',

        'missing_zero_check': 'Arithmetic Issues',
        'incorrect_equality': 'Arithmetic Issues',
        'boolean_equal': 'Arithmetic Issues',
        'divide_before_multiply': 'Arithmetic Issues',

        'weak_prng': 'Bad Randomness',

        'calls_loop': 'Denial of Service',
        'calls-loop': 'Denial of Service',
        'controlled_array_length': 'Denial of Service',
        'locked_ether': 'Denial of Service',
        'return_bomb': 'Denial of Service',

        'reentrancy-benign': 'REENTRANCY',
        'reentrancy_benign': 'REENTRANCY',
        'reentrancy-eth': 'REENTRANCY',
        'reentrancy_eth': 'REENTRANCY',
        'reentrancy-no-eth': 'REENTRANCY',
        'reentrancy_no_eth': 'REENTRANCY',
        'reentrancy_events': 'REENTRANCY',
        'reentrancy_unlimited_gas': 'REENTRANCY',

        'timestamp': 'Time Manipulation',

        'unused-return': 'Unchecked Return Values',
        'unused_return': 'Unchecked Return Values',
        'low-level-calls': 'Unchecked Return Values',
        'low_level-calls': 'Unchecked Return Values',
        'low_level_calls': 'Unchecked Return Values',
        'unchecked_lowlevel': 'Unchecked Return Values',
        'unchecked_send': 'Unchecked Return Values',
        'unchecked_transfer': 'Unchecked Return Values',

        'incorrect-equality': 'Unknown Unknowns',
        'locked-ether': 'Unknown Unknowns',
        'uninitialized-local': 'Unknown Unknowns',
        'uninitialized_local': 'Unknown Unknowns',
        'uninitialized-state': 'Unknown Unknowns',
        'uninitialized-storage': 'Unknown Unknowns',
        'uninitialized_state': 'Unknown Unknowns',
        'uninitialized_storage': 'Unknown Unknowns',
        'shadowing_state': 'Unknown Unknowns',
        'encode_packed_collision': 'Unknown Unknowns',
        'tautology': 'Unknown Unknowns',
        "reentrancy": "Reentrancy",
        "reentrant": "Reentrancy",
        "external call": "Reentrancy",

        "overflow": "Arithmetic Issues",
        "underflow": "Arithmetic Issues",
        "integer arithmetic": "Arithmetic Issues",
        "arithmetic": "Arithmetic Issues",

        "access control": "Access Control",
        "authorization": "Access Control",
        "permissions": "Access Control",
        "tx.origin": "Access Control",
        "constructor name": "Access Control",
        "arbitrary write": "Access Control",

        "random": "Bad Randomness",
        "randomness": "Bad Randomness",

        "dos": "Denial of Service",
        "denial of service": "Denial of Service",
        "gas limit": "Denial of Service",

        "front run": "Front-Running",
        "transaction order": "Front-Running",
        "race condition": "Front-Running",

        "block value": "Time Manipulation",
        "time": "Time Manipulation",

        "unchecked return value from external call.": "Unchecked Return Values",
        "unchecked": "Unchecked Return Values",
        "return value": "Unchecked Return Values",
        "low level call": "Unchecked Return Values",
        "send": "Unchecked Return Values",
        "call": "Unchecked Return Values",

        "short address": "Short Address/Parameter Attack",
        "parameter": "Short Address/Parameter Attack",

        "unchecked-lowlevel": "Unchecked Return Values",
        "unchecked-send": "Unchecked Return Values",
        "unchecked-transfer": "Unchecked Return Values",

        "controlled-array-length": "Access Control",

        "divide-before-multiply": "Arithmetic Issues",

        "weak-prng": "Bad Randomness",

        'assembly': 'ignore',
        'constable-states': 'ignore',
        'constable_states': 'ignore',
        'constant-function': 'ignore',
        'constant_function': 'ignore',
        'deprecated-standards': 'ignore',
        'erc20-indexed': 'ignore',
        'erc20_indexed': 'ignore',
        'erc20_interface': 'ignore',
        'shadowing_abstract': 'ignore',
        'shadowing_builtin': 'ignore',
        'shadowing_local': 'ignore',
        'erc20-interface': 'ignore',
        'external-function': 'ignore',
        'naming-convention': 'ignore',
        'shadowing-abstract': 'ignore',
        'shadowing-builtin': 'ignore',
        'shadowing-local': 'ignore',
        'solc-version': 'ignore',
        'unused-state': 'ignore',
        'solc_version': 'ignore',
        'deprecated_standards': 'ignore',
        'external_function': 'ignore',
        'naming_convention': 'ignore',
        'constant_function_asm': 'ignore',
        'redundant_statements': 'ignore',
        'unused_state': 'ignore',
        'dead_code': 'ignore',
        'events_maths': 'ignore',
        'missing_inheritance': 'ignore',
        'too_many_digits': 'ignore',
        'events_access': 'ignore',
        'costly_loop': 'ignore',
        'cache_array_length': 'ignore'
    },

    'smartcheck': {
        'SOLIDITY_ARRAY_LENGTH_MANIPULATION': 'Arithmetic Issues',
        'SOLIDITY_CALL_WITHOUT_DATA': 'REENTRANCY',
        'SOLIDITY_DIV_MUL': 'Arithmetic Issues',
        'SOLIDITY_EXACT_TIME': 'Time Manipulation',
        'SOLIDITY_GAS_LIMIT_IN_LOOPS': 'Denial of Service',
        'SOLIDITY_SEND': 'Unchecked Return Values',
        'SOLIDITY_TRANSFER_IN_LOOP': 'Denial of Service',
        'SOLIDITY_TX_ORIGIN': 'Access Control',
        'SOLIDITY_UINT_CANT_BE_NEGATIVE': 'Arithmetic Issues',
        'SOLIDITY_UNCHECKED_CALL': 'Unchecked Return Values',
        'SOLIDITY_VAR': 'Arithmetic Issues',
        'SOLIDITY_VAR_IN_LOOP_FOR': 'Arithmetic Issues',
        'SOLIDITY_ADDRESS_HARDCODED': 'ignore',
        'SOLIDITY_BALANCE_EQUALITY': 'Unknown Unknowns',
        'SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES': 'ignore',
        'SOLIDITY_DEPRECATED_CONSTRUCTIONS': 'ignore',
        'SOLIDITY_ERC20_APPROVE': 'ignore',
        'SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE': 'ignore',
        'SOLIDITY_ERC20_TRANSFER_SHOULD_THROW': 'ignore',
        'SOLIDITY_EXTRA_GAS_IN_LOOPS': 'ignore',
        'SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN': 'Unknown Unknowns',
        'SOLIDITY_INCORRECT_BLOCKHASH': 'Unknown Unknowns',
        'SOLIDITY_LOCKED_MONEY': 'Unknown Unknowns',
        'SOLIDITY_MSGVALUE_EQUALS_ZERO': 'ignore',
        'SOLIDITY_OVERPOWERED_ROLE': 'ignore',
        'SOLIDITY_PRAGMAS_VERSION': 'ignore',
        'SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA': 'ignore',
        'SOLIDITY_REDUNDANT_FALLBACK_REJECT': 'ignore',
        'SOLIDITY_REVERT_REQUIRE': 'ignore',
        'SOLIDITY_SAFEMATH': 'ignore',
        'SOLIDITY_SHOULD_NOT_BE_PURE': 'ignore',
        'SOLIDITY_SHOULD_NOT_BE_VIEW': 'ignore',
        'SOLIDITY_SHOULD_RETURN_STRUCT': 'ignore',
        'SOLIDITY_UPGRADE_TO_050': 'ignore',
        'SOLIDITY_USING_INLINE_ASSEMBLY': 'ignore',
        'SOLIDITY_VISIBILITY': 'ignore',
        'SOLIDITY_WRONG_SIGNATURE': 'ignore'
    },
    'semgrep': {
        'delegatecall_to_arbitrary_address': 'Access Control',
        'incorrect_use_of_blockhash': 'Bad Randomness',
        'use_ownable2step': 'Access Control',

        # Gas Optimization/Code Style Issues (not security vulnerabilities)
        'inefficient_state_variable_increment': 'ignore',
        'non_payable_constructor': 'ignore',
        'use_prefix_decrement_not_postfix': 'ignore',
        'use_multiple_require': 'ignore',
        'array_length_outside_loop': 'ignore',
        'state_variable_read_in_a_loop': 'ignore',
        'unnecessary_checked_arithmetic_in_loop': 'ignore',
        'use_nested_if': 'ignore',
        'use_prefix_increment_not_postfix': 'ignore',
        'init_variables_with_default_value': 'ignore',
        'use_custom_error_not_require': 'ignore',
        'use_short_revert_string': 'ignore'
    },
    'solhint': {
        'avoid_low_level_calls': 'Unchecked Return Values',
        'check_send_result': "Unchecked Return Values",
        'avoid_call_value': 'Unchecked Return Values',
        'not_rely_on_time': 'Time Manipulation',
        'not_rely_on_block_hash': 'Time Manipulation',
        'reentrancy': 'REENTRANCY',
        'state_visibility': 'Access Control',
        'func_visibility': 'Access Control',
        'multiple_send': 'Unchecked Return Values',
        'no_complex_fallback': 'REENTRANCY',
        'payable_fallback': 'Denial of Service',
        'no_inline_assembly': 'Unknown Unknowns',
        'avoid_sha3': 'Unknown Unknowns',
        'indent': 'ignore',
        'max-line-length': 'ignore',
        'avoid_tx_origin': 'Access Control',
        'multiple_sends': 'Unchecked Return Values',
        'func_name_mixedcase': 'ignore',
        'reason_string': 'ignore',
        'var_name_mixedcase': 'ignore',
        'visibility_modifier_order': 'ignore',
        'compiler_version': 'ignore',
        'no_unused_vars': 'ignore',
        'avoid_throw': 'ignore',
        'no_empty_blocks': 'ignore',
        'contract_name_camelcase': 'ignore',
        'const_name_snakecase': 'ignore',
        'quotes': 'ignore'
    }
}


def create_output_file_to_dasp_mapping():
    """
    Creates a mapping from output file names to their corresponding DASP categories.

    Returns:
        dict: Dictionary mapping output file names to DASP categories
    """
    return {
        'output_access_control.csv': 'Access Control',
        'output_arithmetic.csv': 'Arithmetic Issues',
        'output_bad_randomness.csv': 'Bad Randomness',
        'output_denial_of_service.csv': 'Denial of Service',
        'output_front_running.csv': 'Front-Running',
        'output_other.csv': 'Unknown Unknowns',
        'output_reentrancy.csv': 'REENTRANCY',
        'output_short_addresses.csv': 'Short Addresses',
        'output_time_manipulation.csv': 'Time Manipulation',
        'output_unchecked_low_level_calls.csv': 'Unchecked Return Values'
    }


def load_ground_truth(gt_file_path):
    """
    Load ground truth data from a CSV file into a pandas DataFrame.

    Args:
        gt_file_path (str): Path to the ground truth CSV file

    Returns:
        pandas.DataFrame: DataFrame containing the ground truth data
    """
    df = pd.read_csv(gt_file_path)
    df = df.drop_duplicates()
    df = df.fillna('')
    return df


def load_smartbugs_dataset(csv_file_path):
    """
    Load SmartBugs raw dataset from CSV file and process it for vulnerability detection metrics.

    Args:
        csv_file_path (str): Path to the SmartBugs raw CSV file

    Returns:
        pandas.DataFrame: Processed DataFrame ready for vulnerability metric calculations
    """
    df = pd.read_csv(csv_file_path)

    result_df = pd.DataFrame(columns=['Tool', 'File', 'Vulnerability', 'SWC-ID', 'Severity', 'DASP', 'duration'])

    for _, row in df.iterrows():
        tool_id = row['toolid']
        file_path = row['source_file']
        basename = row['basename']
        findings = row.get('findings', '')
        duration = row['duration']

        # if pd.isna(findings) or findings == '':
        #     continue

        try:
            findings_data = parse_findings_json(findings, tool_id)[0]

            if tool_id.lower() == 'mythril':
                for finding in findings_data:
                    new_row = {
                        'Tool': tool_id,
                        'File': basename,
                        'Vulnerability': finding,
                        'SWC-ID': '', #finding.get('swc-id', ''),
                        'Severity': '', # finding.get('severity', 'Unknown'),
                        'DASP': '',  # Will be filled later by add_dasp_column
                        'duration': duration
                    }
                    result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)

            elif tool_id.lower() == 'slither':
                for finding in findings_data:
                    new_row = {
                        'Tool': tool_id,
                        'File': basename,
                        # 'Vulnerability': finding.get('check', ''),
                        'Vulnerability': finding,
                        'SWC-ID': '',  # Slither doesn't use SWC-ID directly
                        'Severity': '', # finding.get('impact', 'Unknown'),
                        'DASP': '',
                        'duration': duration
                    }
                    result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)

            else:
                for finding in findings_data if isinstance(findings_data, list) else [findings_data]:
                    new_row = {
                        'Tool': tool_id,
                        'File': basename,
                        'Vulnerability': str(finding),
                        'SWC-ID': '',
                        'Severity': 'Unknown',
                        'DASP': '',
                        'duration': duration

                    }
                    result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)
        except Exception as e:
            print(f"Error processing findings for {file_path} with tool {tool_id}: {str(e)}")

    return result_df


def parse_findings_json(findings_string, tool_id):
    """
    Parse JSON findings data from tool output.

    Args:
        findings_string (str): JSON string containing findings data
        tool_id (str): ID of the tool that generated the findings

    Returns:
        list: List of parsed findings
    """
    if pd.isna(findings_string) or findings_string == '':
        return []

    if findings_string.startswith('{') and findings_string.endswith('}'):
        findings_string = findings_string[1:-1]

    elements = [elem.strip() for elem in findings_string.split(',')]
    return [elements]


def get_filename(path):
    if pd.isna(path):
        return path
    return extract_filename(path)


def map_swc_to_dasp(swc_id_string, description=None):
    # Extract SWC ID
    swc_id = extract_swc_id(swc_id_string)
    # print(f"SWC ID: {swc_id}")
    return determine_dasp_category(swc_id, description)


def map_slither_detector_to_dasp(detector):
    if not isinstance(detector, str):
        return "Unknown Unknowns"

    swc_to_dasp = build_swc_dasp_mapping()
    swc_id = slither_detector_to_swc(detector)

    if swc_id is not None:
        swc_id_str = str(swc_id)
        if swc_id_str in swc_to_dasp:
            return swc_to_dasp[swc_id_str]

    return determine_dasp_category(None, detector)


def map_vulnerability_to_dasp(tool_name, vulnerability):
    """
    Maps a tool-specific vulnerability to a DASP category.

    Args:
        tool_name (str): The name of the vulnerability detection tool
        vulnerability (str): The vulnerability as reported by the tool

    Returns:
        str: The corresponding DASP category
    """
    if vulnerability == "":
        return "empty"

    tool_name = tool_name.lower()

    if tool_name in TOOL_VULNERABILITY_MAP:
        if vulnerability in TOOL_VULNERABILITY_MAP[tool_name]:
            dasp_category = TOOL_VULNERABILITY_MAP[tool_name][vulnerability]
            return dasp_category

    return 'Uncategorized'

def add_dasp_column(results_df, tool_name):
    empty_mask = results_df['SWC-ID'].isna() | (results_df['SWC-ID'] == '')
    if 'mythril' in tool_name.lower():
        mythril_mask = results_df['Tool'] == 'mythril'

        if 'SWC-ID' in results_df.columns and 'Vulnerability' in results_df.columns:
            if empty_mask.any():
                results_df.loc[mythril_mask, 'DASP'] = results_df.apply(
                    lambda row: map_vulnerability_to_dasp(tool_name, row['Vulnerability']), axis = 1)
            else:
                results_df.loc[mythril_mask,'DASP'] = results_df.apply(
                    lambda row: map_swc_to_dasp(row['SWC-ID'], row['Vulnerability']), axis=1
                )
        elif 'SWC ID' in results_df.columns and 'Vulnerability' in results_df.columns:
            results_df.loc[mythril_mask,'DASP'] = results_df.apply(
                lambda row: map_swc_to_dasp(row['SWC ID'], row['Vulnerability']), axis=1
            )
        elif 'SWC-ID' in results_df.columns:
            results_df.loc[mythril_mask,'DASP'] = results_df['SWC-ID'].apply(map_swc_to_dasp)
        elif 'SWC ID' in results_df.columns:
            results_df.loc[mythril_mask,'DASP'] = results_df['SWC ID'].apply(map_swc_to_dasp)
        elif 'swc_id' in results_df.columns:
            results_df.loc[mythril_mask,'DASP'] = results_df['swc_id'].apply(map_swc_to_dasp)

    elif 'slither' in tool_name.lower():
        slither_mask = results_df['Tool'] == 'slither'
        results_df.loc[slither_mask, 'DASP'] = results_df.apply(
            lambda row: map_vulnerability_to_dasp(tool_name, row['Vulnerability']), axis=1)
    else:
        if 'Vulnerability' in results_df.columns:
                results_df['DASP'] = results_df.apply(
                lambda row: map_vulnerability_to_dasp(row['Tool'], row['Vulnerability']), axis=1
            )
    if 'DASP' not in results_df.columns:
        if 'Category' in results_df.columns:
            results_df['DASP'] = results_df['Category']
        else:
            results_df['DASP'] = "Unknown Unknowns"


def calculate_detection_metrics(ground_truth_df, tool_results_df, dasp_category=None):
    """
    Calculate detection metrics for each tool.

    Args:
        ground_truth_df (pandas.DataFrame): DataFrame containing ground truth data
        tool_results_df (pandas.DataFrame): DataFrame containing tool results
        dasp_category (str, optional): Filter by DASP category

    Returns:
        dict: Dictionary containing metrics for each tool
    """
    results_df = tool_results_df.copy()

    required_columns = ['Tool', 'File','Vulnerability', 'DASP']
    for col in required_columns:
        if col not in results_df.columns:
            if col == 'DASP' and 'Category' in results_df.columns:
                results_df['DASP'] = results_df['Category']
            else:
                print(f"Warning: Required column '{col}' not found in results")
                if col == 'Tool':
                    results_df['Tool'] = 'Unknown'
                elif col == 'DASP':
                    results_df['DASP'] = 'Unknown Unknowns'


    filtered_ground_truth_df = ground_truth_df

    metrics = {}

    tools = results_df['Tool'].unique() if 'Tool' in results_df.columns else ['Unknown']

    for tool in tools:
        print(f"===== Processing results for {tool}")
        add_dasp_column(results_df, tool)

        tool_data = results_df[results_df['Tool'] == tool].copy() if 'Tool' in results_df.columns else results_df.copy()

        tool_data = tool_data[['Tool', 'File','Vulnerability', 'DASP']]#.drop_duplicates().reset_index(drop=True)

        if "File" not in tool_data.columns:
            print(f"Error: 'File' column not found in results for tool {tool} ")
            continue

        tool_data["File"] = tool_data["File"].apply(get_filename)

        detected_files_with_categories = tool_data[['File', 'Vulnerability', 'DASP']].drop_duplicates().reset_index(drop=True)

        detected_files = {}
        for _, row in detected_files_with_categories.iterrows():
            file_name = row['File']
            category = row['DASP']

            if file_name not in detected_files:
                detected_files[file_name] = set()
            detected_files[file_name].add(category)

            overall_metrics = {
                'TP': 0,
                'FP': 0,
                'FN': 0,
                'TN': 0,
                'Precision': 0,
                'Recall': 0,
                'F1': 0,
                'Samples': 0
            }

            category_metrics = {}

            counted_file_category_pairs = set()

            for _, gt_row in filtered_ground_truth_df.iterrows():
                gt_file = gt_row['Filename']
                gt_category = gt_row['DASP']

                if gt_category not in category_metrics:
                    category_metrics[gt_category] = {
                        'TP': 0,
                        'FP': 0,
                        'FN': 0,
                        'TN': 0,
                        'Precision': 0,
                        'Recall': 0,
                        'F1': 0,
                        'Samples': 0
                    }

                if gt_file in detected_files:
                    detected_categories = detected_files[gt_file]

                    correct_category_detected = False

                    for detected_category in detected_categories:
                        if (gt_file, detected_category) not in counted_file_category_pairs:
                            file_category_pair = (gt_file, detected_category)

                            if detected_category.lower() == gt_category.lower():
                                # Detected with the correct category
                                overall_metrics['TP'] += 1
                                category_metrics[gt_category]['TP'] += 1
                                correct_category_detected = True
                                # if gt_category== "Access Control" and tool== "slither" :
                                #     print(
                                #         f"True Positive: detected='{detected_category}', ground truth='{gt_category}' for file '{gt_file}' for tool '{tool}'")
                                counted_file_category_pairs.add(file_category_pair)
                            else:
                                # Detected but with wrong category - FP for the detected category
                                # if gt_category == "Access Control" and tool == "mythril":
                                #     print(
                                #         f"Mismatch: detected='{detected_category}', ground truth='{gt_category}' for file '{gt_file}' for tool '{tool}'")
                                # Detected but with wrong category
                                overall_metrics['FP'] += 1

                                # Initialize detected category if not present
                                if detected_category not in category_metrics:
                                    category_metrics[detected_category] = {
                                        'TP': 0,
                                        'FP': 0,
                                        'FN': 0,
                                        'TN': 0,
                                        'Precision': 0,
                                        'Recall': 0,
                                        'F1': 0,
                                        'Samples': 0
                                    }

                                category_metrics[detected_category]['FP'] += 1

                                counted_file_category_pairs.add(file_category_pair)

                    if not correct_category_detected:
                        overall_metrics['FN'] += 1
                        category_metrics[gt_category]['FN'] += 1
                        file_category_pair = (gt_file, gt_category)
                        counted_file_category_pairs.add(file_category_pair)

            overall_metrics['Precision'] = (
                overall_metrics['TP'] / (overall_metrics['TP'] + overall_metrics['FP'])
                if (overall_metrics['TP'] + overall_metrics['FP']) > 0 else 0
            )
            overall_metrics['Recall'] = (
                overall_metrics['TP'] / (overall_metrics['TP'] + overall_metrics['FN'])
                if (overall_metrics['TP'] + overall_metrics['FN']) > 0 else 0
            )
            overall_metrics['F1'] = (
                2 * overall_metrics['Precision'] * overall_metrics['Recall'] / (
                            overall_metrics['Precision'] + overall_metrics['Recall'])
                if (overall_metrics['Precision'] + overall_metrics['Recall']) > 0 else 0
            )
            overall_metrics['Samples'] = len(counted_file_category_pairs)

            for category, metrics_dict in category_metrics.items():
                metrics_dict['Precision'] = (
                    metrics_dict['TP'] / (metrics_dict['TP'] + metrics_dict['FP'])
                    if (metrics_dict['TP'] + metrics_dict['FP']) > 0 else 0
                )
                metrics_dict['Recall'] = (
                    metrics_dict['TP'] / (metrics_dict['TP'] + metrics_dict['FN'])
                    if (metrics_dict['TP'] + metrics_dict['FN']) > 0 else 0
                )
                metrics_dict['F1'] = (
                    2 * metrics_dict['Precision'] * metrics_dict['Recall'] / (
                                metrics_dict['Precision'] + metrics_dict['Recall'])
                    if (metrics_dict['Precision'] + metrics_dict['Recall']) > 0 else 0
                )
                metrics_dict['Samples'] = sum([1 for pair in counted_file_category_pairs if pair[1] == category])

            metrics[tool] = {
                'overall': overall_metrics,
                'by_category': category_metrics
            }

    return metrics


def print_metrics_summary(metrics):
    """
    Print a detailed summary of detection metrics for each tool, including per-category breakdown.

    Args:
        metrics: Dictionary with metrics for each tool and category
    """
    print("\n===== Detection Metrics Summary =====")

    for tool, tool_metrics in metrics.items():
        overall = tool_metrics['overall']
        by_category = tool_metrics['by_category']

        print(f"\n----- Tool: {tool} -----")
        print(f"Overall Metrics:")
        print(f"  TP: {overall['TP']}, FP: {overall['FP']}, FN: {overall['FN']}")
        print(f"  Precision: {overall['Precision']:.4f}, Recall: {overall['Recall']:.4f}, F1: {overall['F1']:.4f}")
        print(f"  Samples: {overall['Samples']}")

        print(f"\nBreakdown by DASP Category:")
        for category, cat_metrics in sorted(by_category.items()):
            if cat_metrics['TP'] + cat_metrics['FP'] + cat_metrics['FN'] > 0:  # Only show categories with data
                print(f"  {category}:")
                print(f"    TP: {cat_metrics['TP']}, FP: {cat_metrics['FP']}, FN: {cat_metrics['FN']}")
                print(f"    Precision: {cat_metrics['Precision']:.4f}, Recall: {cat_metrics['Recall']:.4f}, F1: {cat_metrics['F1']:.4f}")


def visualize_tool_performance_by_category(metrics, output_file='tool_category_performance.pdf'):
    """
    Create visualizations of tool performance metrics broken down by DASP category.

    Args:
        metrics: Dictionary containing metrics for each tool and category
        output_file: Path to save the visualization
    """
    all_categories = set()
    for tool_metrics in metrics.values():
        all_categories.update(tool_metrics['by_category'].keys())

    all_categories = sorted(all_categories)

    plt.figure(figsize=(20, 15))

    fig, axes = plt.subplots(3, 1, figsize=(15, 18))
    metric_names = ['Precision', 'Recall', 'F1']

    for i, metric_name in enumerate(metric_names):
        ax = axes[i]

        tool_names = []
        category_data = {category: [] for category in all_categories}

        sorted_tools = sorted(
            metrics.items(),
            key=lambda x: x[1]['overall']['F1'],
            reverse=True
        )

        for tool, tool_metrics in sorted_tools:
            tool_names.append(tool)
            for category in all_categories:
                if category in tool_metrics['by_category']:
                    category_data[category].append(tool_metrics['by_category'][category][metric_name])
                else:
                    # No data for this category
                    category_data[category].append(0)

        x = np.arange(len(tool_names))
        bar_width = 0.8 / len(all_categories)

        for j, category in enumerate(all_categories):
            ax.bar(
                x + j * bar_width - 0.4 + (bar_width / 2),
                category_data[category],
                bar_width,
                label=category,
                alpha=0.7
            )

        ax.set_xlabel('Tools')
        ax.set_ylabel(metric_name)
        ax.set_title(f'{metric_name} by Tool and DASP Category')
        ax.set_xticks(x)
        ax.set_xticklabels(tool_names, rotation=45, ha='right')
        ax.set_ylim(0, 1)
        ax.grid(axis='y', linestyle='--', alpha=0.7)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(0.5, 0.05), ncol=3)

    plt.tight_layout(rect=[0, 0.1, 1, 0.95])  # Make room for the legend
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Category performance visualization saved to {output_file}")


def analyze_by_tool(ground_truth_df, output_files):
    """
    Analyze results by tool using DataFrame operations.

    Args:
        ground_truth_df (pandas.DataFrame): DataFrame containing ground truth data
        output_files list[str]: Directory containing results files

    Returns:
        dict: Dictionary containing analysis results by tool and category
    """
    file_to_category_map = create_output_file_to_dasp_mapping()

    combined_metrics = {}

    for output_file in output_files:
        if output_file.name.endswith('.csv'):
            dasp_category = file_to_category_map[output_file.name]

            try:
                detected_df = pd.read_csv(output_file)

                if dasp_category:
                    file_metrics = calculate_detection_metrics(ground_truth_df, detected_df, dasp_category)
                else:
                    file_metrics = calculate_detection_metrics(ground_truth_df, detected_df)

                for tool, tool_metrics in file_metrics.items():
                    if tool not in combined_metrics:
                        combined_metrics[tool] = {
                            'overall': {
                                'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0,
                                'Precision': 0, 'Recall': 0, 'F1': 0, 'Samples': 0
                            },
                            'by_category': {}
                        }

                    combined_metrics[tool]['overall']['TP'] += tool_metrics['overall']['TP']
                    combined_metrics[tool]['overall']['FP'] += tool_metrics['overall']['FP']
                    combined_metrics[tool]['overall']['FN'] += tool_metrics['overall']['FN']
                    combined_metrics[tool]['overall']['TN'] += tool_metrics['overall']['TN']
                    combined_metrics[tool]['overall']['Samples'] += tool_metrics['overall']['Samples']

                    for category, cat_metrics in tool_metrics['by_category'].items():
                        if category not in combined_metrics[tool]['by_category']:
                            combined_metrics[tool]['by_category'][category] = {
                                'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0,
                                'Precision': 0, 'Recall': 0, 'F1': 0, 'Samples': 0
                            }

                        combined_metrics[tool]['by_category'][category]['TP'] += cat_metrics['TP']
                        combined_metrics[tool]['by_category'][category]['FP'] += cat_metrics['FP']
                        combined_metrics[tool]['by_category'][category]['FN'] += cat_metrics['FN']
                        combined_metrics[tool]['by_category'][category]['TN'] += cat_metrics['TN']
                        combined_metrics[tool]['by_category'][category]['Samples'] += cat_metrics['Samples']
            except Exception as e:
                print(f"Error processing {output_file}: {str(e)}")

    for tool, tool_metrics in combined_metrics.items():
        tp = tool_metrics['overall']['TP']
        fp = tool_metrics['overall']['FP']
        fn = tool_metrics['overall']['FN']

        tool_metrics['overall']['Precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
        tool_metrics['overall']['Recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
        tool_metrics['overall']['F1'] = (
            2 * tool_metrics['overall']['Precision'] * tool_metrics['overall']['Recall'] /
            (tool_metrics['overall']['Precision'] + tool_metrics['overall']['Recall'])
            if (tool_metrics['overall']['Precision'] + tool_metrics['overall']['Recall']) > 0 else 0
        )

        for category, cat_metrics in tool_metrics['by_category'].items():
            tp = cat_metrics['TP']
            fp = cat_metrics['FP']
            fn = cat_metrics['FN']

            cat_metrics['Precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
            cat_metrics['Recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
            cat_metrics['F1'] = (
                2 * cat_metrics['Precision'] * cat_metrics['Recall'] /
                (cat_metrics['Precision'] + cat_metrics['Recall'])
                if (cat_metrics['Precision'] + cat_metrics['Recall']) > 0 else 0
            )

    return combined_metrics


def analyze_by_contract(output_files, ground_truth_data):
    """
    Analyze vulnerability detection results broken down by smart contract file.

    Args:
        output_files: List of output CSV files
        ground_truth_data: Dictionary of ground truth data

    Returns:
        Dictionary containing the analysis by contract
    """
    contract_results = defaultdict(lambda: {
        'true_positives': 0,
        'true_negatives': 0,
        'false_positives': 0,
        'false_negatives': 0,
        'tools_detected': set(),
        'vuln_prob': 0.0,
        'by_tool': defaultdict(lambda: {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'vuln_prob': 0.0,
        }),
        'ground_truth_category': None
    })

    for output_file in output_files:
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'Tool' not in row or 'File' not in row:
                    continue

                tool = row['Tool']
                file_path = row['File']
                file_path = clean_file_path(file_path)
                filename = extract_filename(file_path)

                vuln_prob = 0.0
                severity = row.get('Severity', '')
                if severity in "High":
                    vuln_prob = 0.8
                elif severity in "Medium":
                    vuln_prob = 0.6
                elif severity in "Low":
                    vuln_prob = 0.4
                else:
                    vuln_prob = 0.1

                if not tool or not file_path:
                    continue

                contract_results[file_path]['tools_detected'].add(tool)

                if tool == "slither":
                    swc_id = slither_detector_to_swc(row.get('Vulnerability', ''))
                else:
                    swc_id = extract_swc_id(row.get('SWC-ID', ''))

                vulnerability = row.get('Vulnerability', '')
                detected_category = determine_dasp_category(swc_id, vulnerability)

                ground_truth = (ground_truth_data.get(file_path) or
                                ground_truth_data.get(filename))

                if ground_truth:
                    contract_results[file_path]['ground_truth_category'] = ground_truth['dasp']

                contract_results[file_path]['vuln_prob'] = vuln_prob
                contract_results[file_path]['by_tool'][tool]['vuln_prob'] = vuln_prob

                metrics = calculate_detection_metrics(detected_category, ground_truth)

                contract_results[file_path]['true_positives'] += metrics['true_positive']
                contract_results[file_path]['false_positives'] += metrics['false_positive']
                contract_results[file_path]['true_negatives'] += metrics['true_negative']
                contract_results[file_path]['false_negatives'] += metrics['false_negative']

                contract_results[file_path]['by_tool'][tool]['true_positives'] += metrics['true_positive']
                contract_results[file_path]['by_tool'][tool]['false_positives'] += metrics['false_positive']
                contract_results[file_path]['by_tool'][tool]['true_negatives'] += metrics['true_negative']
                contract_results[file_path]['by_tool'][tool]['false_negatives'] += metrics['false_negative']

    for file_path, results in contract_results.items():
        tp = results['true_positives']
        fp = results['false_positives']

        results['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
        results['tools_detected_count'] = len(results['tools_detected'])

        for tool, tool_results in results['by_tool'].items():
            tool_tp = tool_results['true_positives']
            tool_fp = tool_results['false_positives']
            tool_results['precision'] = tool_tp / (tool_tp + tool_fp) if (tool_tp + tool_fp) > 0 else 0

    return contract_results



def generate_tool_breakdown_report(tool_results):
    """
    Generate a detailed report of the performance breakdown by tool.

    Args:
        tool_results: Dictionary containing the analysis by tool
    """
    print("\n" + "=" * 80)
    print(" " * 20 + "VULNERABILITY DETECTION PERFORMANCE BY TOOL")
    print("=" * 80)

    sorted_tools = sorted(
        tool_results.items(),
        key=lambda x: x[1].get('f1_score', 0),
        reverse=True
    )

    print("\n{:<15} {:<8} {:<8} {:<8} {:<8} {:<10} {:<10} {:<10} {:<10}".format(
        "Tool", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1 Score", "VD-S"))
    print("-" * 80)

    for tool, results in sorted_tools:
        print("{:<15} {:<8} {:<8} {:<8} {:<8} {:<10.4f} {:<10.4f} {:<10.4f} {:<10.4f}".format(
            tool,
            results.get('true_positives', 0),
            results.get('false_positives', 0),
            results.get('false_negatives', 0),
            results.get('true_negatives', 0),
            results.get('precision', 0),
            results.get('recall', 0),
            results.get('f1_score', 0),
            results.get('vd_score', 1.0)
        ))

    for tool, results in sorted_tools:
        print("\n" + "-" * 40)
        print(f"Detailed Analysis for Tool: {tool}")
        print("-" * 40)

        # print(f"Files Analyzed: {results['files_analyzed_count']}")
        print(f"True Positives: {results['true_positives']}")
        print(f"False Positives: {results['false_positives']}")
        print(f"True Negatives: {results['true_positives']}")
        print(f"False Negatives: {results.get('false_negatives', 0)}")
        print(f"Precision: {results.get('precision', 0):.4f}")
        print(f"Recall: {results.get('recall', 0):.4f}")
        print(f"F1 Score: {results.get('f1_score', 0):.4f}")

        print(f"\nPerformance by Category for Tool: {tool}")

        categories = set(results['by_category'].keys())
        if 'by_category_false_negatives' in results:
            categories.update(results['by_category_false_negatives'].keys())

        for category in sorted(categories):
            cat_results = results['by_category'].get(category, {})
            cat_tp = cat_results.get('true_positives', 0)
            cat_fp = cat_results.get('false_positives', 0)
            cat_fn = results.get('by_category_false_negatives', {}).get(category, 0)


            cat_precision = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0
            cat_recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0
            cat_f1 = 2 * (cat_precision * cat_recall) / (cat_precision + cat_recall) if (
                                                                                                cat_precision + cat_recall) > 0 else 0


            print(f"  {category}:")
            print(f"    TP: {cat_tp}, FP: {cat_fp}, FN: {cat_fn}")
            print(
                f"    Precision: {cat_precision:.4f}, Recall: {cat_recall:.4f}, F1: {cat_f1:.4f}")


def visualize_tool_performance(tool_results, output_file='tool_performance.pdf'):
    """
    Create visualizations of tool performance metrics.

    Args:
        tool_results: Dictionary containing the analysis by tool
        output_file: Path to save the visualization
    """
    tools = []
    precisions = []
    recalls = []
    f1_scores = []

    sorted_tools = sorted(
        tool_results.items(),
        key=lambda x: x[1].get('f1_score', 0),
        reverse=True
    )

    for tool, results in sorted_tools:
        tools.append(tool)
        precisions.append(results.get('precision', 0))
        recalls.append(results.get('recall', 0))
        f1_scores.append(results.get('f1_score', 0))

    plt.figure(figsize=(12, 8))

    x = np.arange(len(tools))
    width = 0.25

    plt.bar(x - width, precisions, width, label='Precision', color='blue', alpha=0.7)
    plt.bar(x, recalls, width, label='Recall', color='green', alpha=0.7)
    plt.bar(x + width, f1_scores, width, label='F1 Score', color='red', alpha=0.7)

    plt.xlabel('Tools')
    plt.ylabel('Score')
    plt.title('Tool Performance Comparison')
    plt.xticks(x, tools, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    plt.ylim(0, 1)

    for i, v in enumerate(precisions):
        plt.text(i - width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    for i, v in enumerate(recalls):
        plt.text(i, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    for i, v in enumerate(f1_scores):
        plt.text(i + width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')


def generate_contract_breakdown_report(tool_results, contract_results, output_file='category_performance.pdf'):
    """
    Generate a detailed report of the performance breakdown by contract.

    Args:
        contract_results: Dictionary containing the analysis by contract
        tool_results: Dictionary containing the analysis by tool
        output_file: Path to save the visualization
    """
    print("\n" + "=" * 80)
    print(" " * 20 + "VULNERABILITY DETECTION PERFORMANCE BY CONTRACT")
    print("=" * 80)

    sorted_contracts = sorted(
        contract_results.items(),
        key=lambda x: x[1].get('f1_score', 0),
        reverse=True
    )

    gt_contracts = [(path, res) for path, res in sorted_contracts if res.get('ground_truth_category')]

    print("\n{:<50} {:<20} {:<8} {:<8} {:<8} {:<10}".format(
        "Contract", "Ground Truth", "TP", "FP", "FN", "F1 Score"))
    print("-" * 110)

    for file_path, results in gt_contracts:
        short_path = extract_filename(file_path)

        print("{:<50} {:<20} {:<8} {:<8} {:<8} {:<10.4f}".format(
            short_path,
            results.get('ground_truth_category', 'N/A'),
            results['true_positives'],
            results['false_positives'],
            results.get('false_negatives', 0),
            results.get('f1_score', 0)
        ))

    print("\nSummary by Ground Truth Category:")

    category_stats = defaultdict(lambda: {
        'contracts': 0,
        'true_positives': 0,
        'false_positives': 0,
        'false_negatives': 0
    })

    for file_path, results in contract_results.items():
        category = results.get('ground_truth_category')
        if category:
            category_stats[category]['contracts'] += 1
            category_stats[category]['true_positives'] += results['true_positives']
            category_stats[category]['false_positives'] += results['false_positives']
            category_stats[category]['false_negatives'] += results.get('false_negatives', 0)

    print("\n{:<25} {:<10} {:<8} {:<8} {:<8} {:<10} {:<10} {:<10} {:<10}".format(
        "Category", "Contracts", "TP", "FP", "FN", "Precision", "Recall", "F1 Score", "VD-S"))
    print("-" * 105)


    categories = []
    precisions = []
    recalls = []
    f1_scores = []

    for category, stats in sorted(category_stats.items()):
        tp = stats['true_positives']
        fp = stats['false_positives']
        fn = stats['false_negatives']

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        categories.append(category)
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)

    plt.figure(figsize=(14, 10))

    x = np.arange(len(categories))
    width = 0.2

    plt.bar(x - 1.5 * width, precisions, width, label='Precision', color='blue', alpha=0.7)
    plt.bar(x - 0.5 * width, recalls, width, label='Recall', color='green', alpha=0.7)
    plt.bar(x + 0.5 * width, f1_scores, width, label='F1 Score', color='red', alpha=0.7)

    plt.xlabel('Vulnerability Categories')
    plt.ylabel('Score')
    plt.title('Performance by Vulnerability Category')
    plt.xticks(x, categories, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    plt.ylim(0, 1)

    for i, v in enumerate(precisions):
        plt.text(i - 1.5 * width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    for i, v in enumerate(recalls):
        plt.text(i - 0.5 * width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    for i, v in enumerate(f1_scores):
        plt.text(i + 0.5 * width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')


def visualize_smartbugs_metrics(metrics, output_file='smartbugs_performance.pdf'):
    """
    Create visualizations specifically for SmartBugs dataset metrics.

    Args:
        metrics (dict): Dictionary of metrics for each tool
        output_file (str): Path to save the visualization
    """
    tools = []
    precision_values = []
    recall_values = []
    f1_values = []

    sorted_tools = sorted(
        metrics.items(),
        key=lambda x: x[1].get('F1', 0),
        reverse=True
    )

    for tool, values in sorted_tools:
        tools.append(tool)
        precision_values.append(values.get('Precision', 0))
        recall_values.append(values.get('Recall', 0))
        f1_values.append(values.get('F1', 0))

    plt.figure(figsize=(14, 10))

    x = np.arange(len(tools))
    width = 0.25

    plt.bar(x - width, precision_values, width, label='Precision', color='blue', alpha=0.7)
    plt.bar(x, recall_values, width, label='Recall', color='green', alpha=0.7)
    plt.bar(x + width, f1_values, width, label='F1 Score', color='red', alpha=0.7)

    plt.xlabel('SmartBugs Tools')
    plt.ylabel('Score')
    plt.title('SmartBugs Tool Performance Comparison')
    plt.xticks(x, tools, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.ylim(0, 1)

    for i, v in enumerate(precision_values):
        plt.text(i - width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    for i, v in enumerate(recall_values):
        plt.text(i, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    for i, v in enumerate(f1_values):
        plt.text(i + width, v + 0.02, f"{v:.2f}", ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')

    print(f"SmartBugs visualization saved to {output_file}")


def main():
    data_folder = 'DATA'
    lightcross_data_folder = Path(data_folder) / 'lightcross'
    output_files = [
        lightcross_data_folder / 'access_control' / 'output_access_control.csv',
        lightcross_data_folder / 'arithmetic' / 'output_arithmetic.csv',
        lightcross_data_folder / 'bad_randomness' / 'output_bad_randomness.csv',
        lightcross_data_folder / 'denial_of_service' / 'output_denial_of_service.csv',
        lightcross_data_folder / 'front_running' / 'output_front_running.csv',
        lightcross_data_folder / 'other' / 'output_other.csv',
        lightcross_data_folder / 'reentrancy' / 'output_reentrancy.csv',
        lightcross_data_folder / 'short_addresses' / 'output_short_addresses.csv',
        lightcross_data_folder / 'time_manipulation' / 'output_time_manipulation.csv',
        lightcross_data_folder / 'unchecked_low_level_calls'/ 'output_unchecked_low_level_calls.csv',
    ]

    ground_truth_file = Path(data_folder) / 'sb_vulnerabilities_dasp.csv'
    smartbugs_file = Path(data_folder) /'smartbugs-raw.csv'

    existing_files = [f for f in output_files if f.exists()]

    print("=== Starting Vulnerability Detection Analysis ===")

    ground_truth_data = load_ground_truth(ground_truth_file)
    print(f"Loaded {len(ground_truth_data)} entries from ground truth")

    print("\n=== Processing SmartBugs Dataset ===")
    try:
        smartbugs_results_df = load_smartbugs_dataset(smartbugs_file)
        print(f"Processed {len(smartbugs_results_df)} findings from SmartBugs dataset")
        tools_mask = smartbugs_results_df['Tool'].isin(['mythril', 'slither'])
        # tools_mask = smartbugs_results_df['Tool'].isin(['slither'])

        smartbugs_results = smartbugs_results_df.loc[tools_mask]
        # smartbugs_results = smartbugs_results_df
        for tool in smartbugs_results['Tool'].unique():
            tool_data = smartbugs_results[smartbugs_results['Tool'] == tool]
            add_dasp_column(tool_data, tool.lower())

        smartbugs_metrics = calculate_detection_metrics(ground_truth_data, smartbugs_results)
        print(f"Calculated metrics for {len(smartbugs_metrics)} tools in SmartBugs dataset")

        print("\n=== SmartBugs Detection Metrics Summary ===")
        print_metrics_summary(smartbugs_metrics)

        # visualize_smartbugs_metrics(smartbugs_metrics, 'smartbugs_performance.pdf')
    except Exception as e:
        print(f"Error processing SmartBugs dataset: {str(e)}")
        smartbugs_metrics = {}
    # existing_files = None
    if existing_files:
        print(f"\n=== Processing {len(existing_files)} Output Files ===")
        try:
            file_results = analyze_by_tool(ground_truth_data, existing_files)
            print("Analyzed existing output files for tool performance")
            print_metrics_summary(file_results)
            visualize_tool_performance(file_results, 'tool_performance.pdf')
            print("\nAnalysis complete. Visualization saved to:")
            print("- tool_performance.pdf")
        except Exception as e:
            print(f"Error processing output files: {str(e)}")
    else:
        print("\nNo output files found for additional analysis")

    print("\n=== Vulnerability Detection Analysis Complete ===")

if __name__ == "__main__":
    main()