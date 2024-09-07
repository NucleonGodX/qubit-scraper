import scrapy
import json
from w3lib.html import remove_tags

class QNAPAdvisorySpider(scrapy.Spider):
    name = 'qnap_advisory'
    
    def __init__(self, *args, **kwargs):
        super(QNAPAdvisorySpider, self).__init__(*args, **kwargs)
        self.items = []  # List to store all scraped items
    
    def start_requests(self):
        try:
            with open('data/all_cves.json', 'r') as f:
                data = json.load(f)
            self.logger.info(f"Successfully loaded input.json with {len(data)} items")
        except FileNotFoundError:
            self.logger.error("input.json file not found. Make sure it exists in the spider's directory.")
            return
        except json.JSONDecodeError:
            self.logger.error("Error decoding input.json. Make sure it's valid JSON.")
            return
        
        request_count = 0
        for item in data:
            if 'QNAP' in item.get('description_source', ''):
                yield scrapy.Request(url=item['org_link'], callback=self.parse, meta={'item': item}, errback=self.errback_httpbin)
                request_count += 1
        
        self.logger.info(f"Generated {request_count} requests")

    def parse(self, response):
        self.logger.info(f"Parsing response from {response.url}")
        item = response.meta['item']
        
        release_date = response.css('p.fs-6.mb-0::text').re_first(r'Release date : (.+)')
        cve_ids = response.css('p.fs-6.mb-0::text').re_first(r'CVE identifier : (.+)')
        severity = response.css('div.w-md-auto h4::text').get()
        
        # Updated selectors for summary and recommendations
        summary = self.extract_section(response, 'Summary')
        recommendations = self.extract_section(response, 'Recommendation')
        
        affected_products = response.css('table.table-bordered tr:not(:first-child)').getall()

        scraped_item = {
            'cve_id': item['cve_id'],
            'published_date': item['published_date'],
            'description_source': item['description_source'],
            'org_link': item['org_link'],
            'release_date': release_date,
            'cve_ids': cve_ids,
            'severity': severity,
            'summary': summary,
            'affected_products': affected_products,
            'recommendations': recommendations
        }
        
        self.items.append(scraped_item)  # Add the scraped item to the list
        self.logger.info(f"Scraped item for CVE-ID: {scraped_item['cve_id']}")
        yield scraped_item

    def extract_section(self, response, section_title):
        # This method extracts content between h3 tags
        section = response.xpath(f'//h3[contains(text(), "{section_title}")]/following-sibling::*')
        content = []
        for element in section:
            if element.xpath('name()').get() == 'h3':
                break
            content.append(element.get())
        return remove_tags(''.join(content)).strip()

    def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure}")

    def closed(self, reason):
        # This method is called when the spider is closed
        # Write the collected items to a JSON file
        with open('data/qnap_advisories_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to qnap_advisories_output.json")