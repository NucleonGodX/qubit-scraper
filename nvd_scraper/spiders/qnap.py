import scrapy
import json
from w3lib.html import remove_tags
from scrapy.http import HtmlResponse
import requests

class QNAPAdvisorySpider(scrapy.Spider):
    name = 'qnap_advisory'
    
    def __init__(self, *args, **kwargs):
        super(QNAPAdvisorySpider, self).__init__(*args, **kwargs)
        self.items = []  # List to store all scraped items
    
    def start_requests(self):
        try:
            with open('data/all_cves.json', 'r') as f:
                self.data = json.load(f)
            self.logger.info(f"Successfully loaded all_cves.json with {len(self.data)} items")
        except FileNotFoundError:
            self.logger.error("all_cves.json file not found. Make sure it exists in the spider's directory.")
            return
        except json.JSONDecodeError:
            self.logger.error("Error decoding all_cves.json. Make sure it's valid JSON.")
            return
        
        # Yield a single dummy request to trigger the spider
        yield scrapy.Request(url='https://example.com', callback=self.parse_all_items)

    def parse_all_items(self, response):
        for item in self.data:
            if 'QNAP' in item.get('description_source', ''):
                self.logger.info(f"Processing item for URL: {item['org_link']}")
                yield self.process_item(item)

    def process_item(self, item):
        try:
            # Make a direct request to the URL
            response = requests.get(item['org_link'])
            html_response = HtmlResponse(url=item['org_link'], body=response.content, encoding='utf-8')
            
            release_date = html_response.css('p.fs-6.mb-0::text').re_first(r'Release date : (.+)')
            severity = html_response.css('div.w-md-auto h4::text').get()
            
            summary = self.extract_section(html_response, 'Summary')
            description = item['description_source']  # Use the description from the input data
            recommendations = self.extract_section(html_response, 'Recommendation')
            
            affected_products = html_response.css('table.table-bordered tr:not(:first-child)').getall()

            scraped_item = {
                'cve_id': item['cve_id'],
                'published_date': item['published_date'],
                'description': description,
                'org_link': item['org_link'],
                'release_date': release_date,
                'severity': severity,
                'summary': summary,
                'affected_products': affected_products,
                'recommendations': recommendations
            }
            
            self.items.append(scraped_item)
            self.logger.info(f"Scraped item for CVE-ID: {scraped_item['cve_id']}")
            return scraped_item
        except Exception as e:
            self.logger.error(f"Error processing item {item['cve_id']}: {str(e)}")
            return None

    def extract_section(self, response, section_title):
        section = response.xpath(f'//h3[contains(text(), "{section_title}")]/following-sibling::*')
        content = []
        for element in section:
            if element.xpath('name()').get() == 'h3':
                break
            content.append(element.get())
        return remove_tags(''.join(content)).strip()

    def closed(self, reason):
        with open('data/qnap_advisories_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to qnap_advisories_output.json")