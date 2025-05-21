# LightCross

LightCross is a lightweight tool for detecting vulnerabilities in Ethereum smart contracts. This tool combines the analysis capabilities of industry-standard security tools like Slither and Mythril to provide a thorough vulnerability assessment framework.

## Features

- Multi-tool analysis: Run Slither, Mythril, or both together for more thorough vulnerability detection
- Batch processing of contract files
- Vulnerability mapping and categorization
- Analysis of multiple vulnerability types:
  - Access Control Issues
  - Bad Randomness
  - Denial of Service
  - Front Running
  - Reentrancy
  - Short Addresses
  - Time Manipulation
  - Unchecked Low-Level Calls
  - Other vulnerability types

## Installation

### Prerequisites

- Python 3.12
- Slither 0.11.0 
- Mythril 0.24.8 

```shell script
# Clone the repository
git clone https://github.com/yourusername/lightcross.git
cd lightcross

# Install Python dependencies
pip install -r requirements.txt

# Install Slither if not already installed
pip install slither-analyzer

# Install Mythril if not already installed
pip install mythril
```


## Usage

### Running LightCross

```shell script
# Basic usage with both tools
./exec-lightcross.sh

# Run with specific tool
./exec-lightcross.sh --tools slither
./exec-lightcross.sh --tools mythril

# Get help
./exec-lightcross.sh --help
```


### Single Contract Analysis

```shell script
python smartvulscan.py path/to/contract.sol
```


### Batch Analysis 

```shell script
python smartvulscan.py path/to/contract/folder --tools both
```


## Project Structure

- `smartvulscan.py`: Core vulnerability scanning engine
- `vulnerability_mapper.py`: Maps detected issues to vulnerability categories
- `run_smartvulscan.py`: Helper script to run the main scanner
- `exec-lightcross.sh`: Main execution script for batch processing
- `lightcross-vulnerability-counter.py`: Counts and summarizes detected vulnerabilities
- `test-contracts/`: Sample contracts for testing
- `smartbugs-dataset/`: Benchmark SB-curated dataset with known vulnerabilities
- `DATA/`: Storage for output data
- `outputs/`: Analysis results and reports
- `ANALYSIS/`: Additional analysis scripts for measuring execution time 

## Analysis Output

LightCross generates CSV outputs that contain:
- Contract name and path
- Detected vulnerabilities 
- Detection tool that identified the issue
- OpenSCV, SWC and DASP mapping

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
