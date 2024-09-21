import scrapy
import json
from datetime import datetime

class CiscoAdvisorySpider(scrapy.Spider):
    name = 'cisco_advisory_spider'
    
    def __init__(self, *args, **kwargs):
        super(CiscoAdvisorySpider, self).__init__(*args, **kwargs)
        self.items = []
    
    def start_requests(self):
        try:
            with open('data/all_cves.json', 'r') as f:
                data = json.load(f)
            self.logger.info(f"Successfully loaded cisco_advisories.json with {len(data)} items")
        except FileNotFoundError:
            self.logger.error("cisco_advisories.json file not found. Make sure it exists in the spider's directory.")
            return
        except json.JSONDecodeError:
            self.logger.error("Error decoding cisco_advisories.json. Make sure it's valid JSON.")
            return
        
        request_count = 0
        for item in data:
            if 'sec.cloudapps.cisco.com' in item.get('org_link', '').lower():
                yield scrapy.Request(url=item['org_link'], callback=self.parse, meta={'item': item}, errback=self.errback_httpbin)
                request_count += 1
        
        self.logger.info(f"Generated {request_count} requests")

    def parse(self, response):
        self.logger.info(f"Parsing response from {response.url}")
        item = response.meta['item']

        severity = response.css('div#severitycirclecontent::text').get().strip()
        summary = ' '.join(response.css('div#summaryfield p::text').getall()).strip()
        recommendations = ' '.join(response.css('div#fixedsoftfield p::text').getall()).strip()

        # Extract fixed releases table content
        fixed_releases = []
        rows = response.css('div#fixedsoftfield table tbody tr')
        for row in rows:
            release = row.css('td:first-child::text').get().strip()
            fixed_release = row.css('td:last-child::text').get().strip()
            fixed_releases.append(f"{release}: {fixed_release}")

        fixed_releases_text = "\n".join(fixed_releases)
        recommendations += "\n\nFixed Releases:\n" + fixed_releases_text

        affected_products = ' '.join(response.css('div#vulnerableproducts p::text').getall()).strip()

        scraped_item = {
            'cve_id': item.get('cve_id'),
            'published_date': item.get('published_date'),
            'description': "Cisco Security Advisory",
            'org_link': response.url,
            'release_date': item.get('release_date'),
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
        with open('data/cisco_advisories_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to cisco_advisories_output.json")