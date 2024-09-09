import scrapy
import json
from w3lib.html import remove_tags
from datetime import datetime

class IBMVulnerabilitySpider(scrapy.Spider):
    name = 'ibm_vulnerability'
    
    def __init__(self, *args, **kwargs):
        super(IBMVulnerabilitySpider, self).__init__(*args, **kwargs)
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
            # Check if the URL is an IBM URL
            if 'ibm' in item.get('org_link', '').lower():
                yield scrapy.Request(url=item['org_link'], callback=self.parse, meta={'item': item}, errback=self.errback_httpbin)
                request_count += 1
        
        self.logger.info(f"Generated {request_count} requests")

    def parse(self, response):
        self.logger.info(f"Parsing response from {response.url}")
        item = response.meta['item']

        cve_ids = response.css('div.field--name-field-vulnerability-details a::text').getall()
        published_date = response.css('div.field--name-field-change-history::text').get()
        if published_date:
            published_date = published_date.split(':')[-1].strip()
        
        severity = self.get_severity(response)
        summary = response.css('div.field--name-field-summary p::text').get()

        affected_products = response.css('div.field--name-field-affected-products table tbody tr').getall()
        affected_products = [remove_tags(product).strip() for product in affected_products]

        # Extract product name, platform, and fix link
        product_name = response.css('div.field--name-field-affected-products table tbody tr td:first-child::text').get()
        platform = response.css('div.field--name-field-affected-products table tbody tr td:nth-child(2)::text').get()
        fix_link = response.css('div.field--name-field-remediation-fixes a::attr(href)').get()

        # Create recommendation sentence
        if product_name and platform and fix_link:
            recommendations = f"For {product_name} on {platform} platforms, it is recommended to apply the latest fix, which can be downloaded from the IBM Fix Central website: {fix_link}"
        else:
            recommendations = "It is recommended to apply the fix as soon as possible, see the IBM security bulletin for more details."

        scraped_item = {
            'cve_id':  item.get('cve_id'),
            'published_date': self.format_date(published_date) if published_date else item.get('published_date'),
            'description_source': "IBM",
            'org_link': response.url,
            'release_date': self.format_date(published_date) if published_date else item.get('published_date'),
            'severity': severity or item.get('severity'),
            'summary': summary or item.get('summary'),
            'affected_products': affected_products,
            'recommendations': recommendations
        }
        
        self.items.append(scraped_item)
        self.logger.info(f"Scraped item for CVE-IDs: {scraped_item['cve_id']}")
        yield scraped_item

    def get_severity(self, response):
        # Look for severity information in multiple locations
        severity_text = response.css('div.field--name-field-vulnerability-details::text').get()
        if not severity_text:
            severity_text = response.css('div.field--name-field-vulnerability-details span::text').get()
        
        if severity_text:
            severity_text = severity_text.lower()
            if 'critical' in severity_text:
                return "Critical"
            elif 'high' in severity_text:
                return "High"
            elif 'medium' in severity_text:
                return "Medium"
            elif 'low' in severity_text:
                return "Low"
        
        # If no direct severity text found, try to extract CVSS score
        cvss_scores = response.css('div.field--name-field-vulnerability-details::text').re(r'CVSS Base score: (\d+\.\d+)')
        if not cvss_scores:
            cvss_scores = response.css('div.field--name-field-vulnerability-details span::text').re(r'(\d+\.\d+)')

        if cvss_scores:
            max_score = max(float(score) for score in cvss_scores)
            if max_score >= 9.0:
                return "Critical"
            elif max_score >= 7.0:
                return "High"
            elif max_score >= 4.0:
                return "Medium"
            else:
                return "Low"
        return None

    def format_date(self, date_string):
        try:
            date_obj = datetime.strptime(date_string.strip(), "%d %b %Y")
            return date_obj.strftime("%B %d, %Y; %I:%M:%S %p -0400")
        except ValueError:
            return date_string  # Return the original string if parsing fails

    def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure}")

    def closed(self, reason):
        with open('data/ibm_vulnerabilities_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to ibm_vulnerabilities_output.json")
