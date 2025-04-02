import logging
import os
import glob
import subprocess
import sys
import argparse


def run_smartvulscan(file_path, tools):
    try:
        # Pass the tools parameter to smartvulscan.py
        subprocess.check_output(['python', 'smartvulscan.py', file_path, '--tools', tools])
    except subprocess.CalledProcessError as e:
        print(f"Error running smartvulscan.py for {file_path}: {e.output.decode('utf-8')}")


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Run vulnerability scanner on Solidity files')
    parser.add_argument('folder_path', help='Path to folder containing Solidity files')
    parser.add_argument('--tools', choices=['slither', 'mythril', 'both'], default='both',
                        help='Specify which tools to run: slither, mythril, or both (default)')

    args = parser.parse_args()

    folder_path = args.folder_path
    tools = args.tools

    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        logging.error(f"Error: {folder_path} is not a valid folder")
        sys.exit(1)

    sol_files = glob.glob(os.path.join(folder_path, '*.sol'))

    if not sol_files:
        logging.warning("No .sol files found in the specified folder.")

    for sol_file in sol_files:
        run_smartvulscan(sol_file, tools)


if __name__ == "__main__":
    main()