import scrapy
import json
from w3lib.html import remove_tags
from datetime import datetime

class WordFenceVulnerabilitySpider(scrapy.Spider):
    name = 'wordfence_vulnerability'
    
    def __init__(self, *args, **kwargs):
        super(WordFenceVulnerabilitySpider, self).__init__(*args, **kwargs)
        self.items = []
    
    def start_requests(self):
        try:
            with open('data/all_cves.json', 'r') as f:
                data = json.load(f)
            self.logger.info(f"Successfully loaded qnap_cves.json with {len(data)} items")
        except FileNotFoundError:
            self.logger.error("qnap_cves.json file not found. Make sure it exists in the spider's directory.")
            return
        except json.JSONDecodeError:
            self.logger.error("Error decoding qnap_cves.json. Make sure it's valid JSON.")
            return
        
        request_count = 0
        for item in data:
            if 'wordfence.com' in item.get('org_link', '').lower():
                yield scrapy.Request(url=item['org_link'], callback=self.parse, meta={'item': item}, errback=self.errback_httpbin)
                request_count += 1
        
        self.logger.info(f"Generated {request_count} requests")

    def parse(self, response):
        self.logger.info(f"Parsing response from {response.url}")
        item = response.meta['item']

        published_date = response.css('tr:contains("Publicly Published") td.text-right::text').get()
        severity = response.css('tr:contains("CVSS") td.text-right::text').get()
        if severity:
            severity = severity.strip().split()[1].strip('()')
        summary = response.css('div.card-body p::text').get()

        # Extracting affected and patched versions
        affected_versions = response.css('tr:contains("Affected Version") td.versions-list li::text').getall()
        patched_versions = response.css('tr:contains("Patched Version") td.versions-list li::text').getall()
        software_slug = response.css('tr:contains("Software Slug") td::text').get().strip()

        affected_products = [
            f"{software_slug} version: {', '.join(affected_versions)}",
        ]

        recommendations = response.css('tr:contains("Remediation") td::text').get()

        scraped_item = {
            'cve_id': item.get('cve_id'),
            'published_date': self.format_date(published_date) if published_date else item.get('published_date'),
            'description': "WordFence",
            'org_link': response.url,
            'release_date': self.format_date(published_date) if published_date else item.get('published_date'),
            'severity': severity or item.get('severity'),
            'summary': summary or item.get('summary'),
            'affected_products': affected_products,
            'recommendations': recommendations or item.get('recommendations')
        }
        
        self.items.append(scraped_item)
        self.logger.info(f"Scraped item for CVE-ID: {scraped_item['cve_id']}")
        yield scraped_item

    def format_date(self, date_string):
        try:
            # First, try to parse the input date string
            date_obj = datetime.strptime(date_string.strip(), "%B %d, %Y")
            # Then, format it to the desired output format
            return date_obj.strftime("%d/%m/%Y")
        except ValueError:
            # If the input format is different, try to parse it as "September 03, 2024; 12:00:00 AM -0400"
            try:
                date_obj = datetime.strptime(date_string.strip(), "%B %d, %Y; %I:%M:%S %p -0400")
                return date_obj.strftime("%d/%m/%Y")
            except ValueError:
                return date_string  # Return the original string if parsing fails

    def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure}")

    def closed(self, reason):
        with open('data/wordfence_vulnerabilities_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to wordfence_vulnerabilities_output.json")