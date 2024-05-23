import logging
import os
import glob
import subprocess
import sys


def run_smartvulscan(file_path):
    try:
        subprocess.check_output(['python', 'smartvulscan.py', file_path])
    except subprocess.CalledProcessError as e:
        print(f"Error running smartvulscan.py for {file_path}: {e.output.decode('utf-8')}")

def main():
    if len(sys.argv) < 2:
        logging.error("Usage: python run_smartvulscan.py <folder_path>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        logging.error(f"Error: {folder_path} is not a valid folder")
        sys.exit(1)

    sol_files = glob.glob(os.path.join(folder_path, '*.sol'))

    if not sol_files:
        logging.warning("No .sol files found in the specified folder.")
    
    for sol_file in sol_files:
        run_smartvulscan(sol_file)

if __name__ == "__main__":
    main()
