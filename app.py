import os
import json
import subprocess
from scrapy.crawler import CrawlerProcess
from nvd_scraper.spiders.nvd_spider import NVDSpider
from pymongo import MongoClient, errors
from flask import Flask, jsonify
from multiprocessing import Process

app = Flask(__name__)

url = os.getenv('MONGODB_URL', 'private')
db_name = os.getenv('DB_NAME', 'private')
collection_name = os.getenv('COLLECTION_NAME', 'private')
#
def run_first_level_scraping():
    """Run the first level of scraping to generate the JSON file with links."""
    process = CrawlerProcess()
    process.crawl(NVDSpider)
    process.start()

def run_second_level_scraping():
    """Run the second level of scraping by calling another Python script."""
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
    
    for file in input_files:
        data = load_json_file(file)
        if isinstance(data, list):
            combined_data.extend(data)
        else:
            combined_data.append(data)
    
    with open(output_file, 'w') as out_file:
        json.dump(combined_data, out_file, indent=2)
    
    for file in input_files:
        os.remove(file)
        print(f"Deleted file: {file}")

    print(f"Successfully combined {len(input_files)} files into {output_file}.")

    all_cves_file = 'data/all_cves.json'
    if os.path.exists(all_cves_file):
        os.remove(all_cves_file)
        print(f"Deleted file: {all_cves_file}")
    else:
        print(f"File {all_cves_file} not found, skipping deletion.")

    return combined_data

def insert_many_vulnerabilities(vulnerabilities):
    """Insert many documents into MongoDB with duplicate handling."""
    client = MongoClient(url)
    db = client[db_name]
    collection = db[collection_name]

    try:
        result = collection.insert_many(vulnerabilities, ordered=False)
        print(f'{len(result.inserted_ids)} documents were inserted successfully')
    except errors.BulkWriteError as bwe:
        for error in bwe.details['writeErrors']:
            if error['code'] == 11000:  # Duplicate key error code
                print(f'Duplicate found and skipped: {error["errmsg"]}')
            else:
                print(f'Error: {error["errmsg"]}')
    except Exception as e:
        print(f'An error occurred: {e}')
    finally:
        client.close()

def run_full_scraper():
    """Run the full scraping process and insert data into MongoDB."""
    os.makedirs('data', exist_ok=True)
    run_first_level_scraping()
    run_second_level_scraping()
    
    ibm_file = 'data/ibm_vulnerabilities_output.json'
    qnap_file = 'data/qnap_advisories_output.json'
    wordfence_file = 'data/wordfence_vulnerabilities_output.json'
    microsoft_file='data/microsoft_vulnerabilities_output.json'
    cisco_file='data/cisco_advisories_output.json'
    firefox_file='data/mozilla_security_advisory_output.json'
    adobe_file='data/adobe_security_advisory_output.json'
    combined_data = combine_json_files('data/vulnerabilities_output.json', ibm_file, qnap_file, wordfence_file, microsoft_file, cisco_file, firefox_file, adobe_file)
    
    insert_many_vulnerabilities(combined_data)
    return len(combined_data)

def run_scraper_in_background():
    """Run the scraper in a background process."""
    scraper_process = Process(target=run_full_scraper)
    scraper_process.start()
    scraper_process.join()

@app.route('/run_scraper', methods=['POST'])
def trigger_scraper():
    try:
        # Start scraper in a background process
        run_scraper_in_background()
        return jsonify({"message": "Scraping process triggered in background."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    client = MongoClient(url)
    db = client[db_name]
    collection = db[collection_name]
    
    try:
        vulnerabilities = list(collection.find({}, {'_id': 0}).limit(1000)) 
        return jsonify(vulnerabilities)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        client.close()

if __name__ == '__main__':
    app.run(debug=True)
