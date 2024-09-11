import scrapy
import json
from w3lib.html import remove_tags
from datetime import datetime

class MicrosoftVulnerabilitySpider(scrapy.Spider):
    name = 'microsoft_vulnerability'
    
    def __init__(self, *args, **kwargs):
        super(MicrosoftVulnerabilitySpider, self).__init__(*args, **kwargs)
        self.items = []
    
    def start_requests(self):
        try:
            with open('data/all_cves.json', 'r') as f:
                data = json.load(f)
            self.logger.info(f"Successfully loaded all_cves.json with {len(data)} items")
        except FileNotFoundError:
            self.logger.error("all_cves.json file not found. Make sure it exists in the spider's directory.")
            return
        except json.JSONDecodeError:
            self.logger.error("Error decoding all_cves.json. Make sure it's valid JSON.")
            return
        
        request_count = 0
        for item in data:
            if 'microsoft.com' in item.get('org_link', '').lower():
                yield scrapy.Request(url=item['org_link'], callback=self.parse, meta={'item': item}, errback=self.errback_httpbin)
                request_count += 1
        
        self.logger.info(f"Generated {request_count} requests")

    def parse(self, response):
        self.logger.info(f"Parsing response from {response.url}")
        item = response.meta['item']

        summary = response.css('h1.ms-fontWeight-semibold::text').get()
        severity = response.css('div.ms-Stack p:contains("Max Severity:")::text').re_first(r'Max Severity: (.+)')
        
        affected_products = response.css('div[data-automation-key="product"]::text').getall()
        affected_products = [f"Affected Product: {product.strip()}" for product in affected_products if product.strip()]

        recommendations = response.css('div.root-144::text').get()

        scraped_item = {
            'cve_id': item.get('cve_id'),
            'published_date': item.get('published_date'),
            'description': "Microsoft",
            'org_link': response.url,
            'release_date': item.get('published_date'),
            'severity': severity,
            'summary': summary,
            'affected_products': affected_products,
            'recommendations': recommendations
        }
        
        self.items.append(scraped_item)
        self.logger.info(f"Scraped item for CVE-ID: {scraped_item['cve_id']}")
        yield scraped_item

    def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure}")

    def closed(self, reason):
        with open('data/microsoft_vulnerabilities_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to microsoft_vulnerabilities_output.json")