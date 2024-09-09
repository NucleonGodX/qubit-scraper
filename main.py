import os
import json
import subprocess
from scrapy.crawler import CrawlerProcess
from nvd_scraper.spiders.nvd_spider import NVDSpider

def run_first_level_scraping():
    """Run the first level of scraping to generate the JSON file with links"""
    process = CrawlerProcess()
    process.crawl(NVDSpider)
    process.start()

def run_second_level_scraping():
    """Run the second level of scraping by calling another Python script"""
    subprocess.run(['python', 'new.py'])

def load_json_file(file_path):
    """Load a JSON file and return its content."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error decoding JSON in file {file_path}.")
        return []

def combine_json_files(output_file, *input_files):
    """Combine the contents of multiple JSON files and write to a new file."""
    combined_data = []
    
    # Load and combine data from input files
    for file in input_files:
        data = load_json_file(file)
        if isinstance(data, list):
            combined_data.extend(data)  # Append lists directly
        else:
            combined_data.append(data)  # Append single items (like dicts)
    
    # Write the combined data to the output file
    with open(output_file, 'w') as out_file:
        json.dump(combined_data, out_file, indent=2)
    
    # Delete the input files after combining
    for file in input_files:
        os.remove(file)
        print(f"Deleted file: {file}")

    print(f"Successfully combined {len(input_files)} files into {output_file}.")

    # Delete the all_cves.json file
    all_cves_file = 'data/all_cves.json'
    if os.path.exists(all_cves_file):
        os.remove(all_cves_file)
        print(f"Deleted file: {all_cves_file}")
    else:
        print(f"File {all_cves_file} not found, skipping deletion.")

def main():
    # Ensure the 'data' directory exists
    os.makedirs('data', exist_ok=True)

    # Run the first level of scraping and wait for it to complete
    run_first_level_scraping()

    # Run the second level of scraping in a new process
    run_second_level_scraping()

    # Combine the JSON files after scraping completes
    ibm_file = 'data/ibm_vulnerabilities_output.json'
    qnap_file = 'data/qnap_advisories_output.json'
    wordfence_file = 'data/wordfence_vulnerabilities_output.json'

    combine_json_files('data/vulnerabilities_output.json', ibm_file, qnap_file, wordfence_file)

if __name__ == "__main__":
    main()
