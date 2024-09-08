import scrapy
from scrapy.http import Request
from urllib.parse import urlencode
from datetime import datetime
import logging
import json
import re

class CiscoVulnerabilitySpider(scrapy.Spider):
    name = 'cisco_vulnerability_spider'
    allowed_domains = ['tools.cisco.com', 'sec.cloudapps.cisco.com']
    base_url = 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x'

    
    def __init__(self, *args, **kwargs):
        super(CiscoVulnerabilitySpider, self).__init__(*args, **kwargs)
        self.start_time = datetime.now()
        self.results = []
        self.page_count = 0
        self.max_pages = 100

    def start_requests(self):
        yield self.get_page_request(0)

    def get_page_request(self, start_index):
        params = {
            'resource': 'CiscoSecurityAdvisory',
            'selectYears': 'all',
            'publicationTypeIDs': 'cisco-sa',
            'startIndex': start_index
        }
        url = f"{self.base_url}?{urlencode(params)}"
        return Request(url, self.parse_search_results, meta={'start_index': start_index}, errback=self.errback_httpbin)

    def parse_search_results(self, response):
        self.logger.info(f"Parsing search results from: {response.url}")
        vulnerability_links = response.css('a[href^="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"]')
        self.logger.info(f"Found {len(vulnerability_links)} vulnerability links on this page")
        
        if not vulnerability_links:
            self.logger.warning(f"No vulnerability links found on {response.url}. This might indicate a problem.")
            return
        
        for link in vulnerability_links:
            vuln_id = link.attrib['href'].split('/')[-1]
            vuln_url = link.attrib['href']
            title = link.css('::text').get().strip()
            
            # Extract the date from the title
            date_match = re.search(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', title)
            published_date = date_match.group(0) if date_match else "Date not found"
            
            yield Request(vuln_url, self.parse_vulnerability_details, meta={
                'vuln_id': vuln_id,
                'published_date': published_date,
                'title': title
            }, errback=self.errback_httpbin)
        
        self.page_count += 1

        if self.page_count < self.max_pages:
            start_index = response.meta['start_index'] + 25  # Cisco uses 25 items per page
            yield self.get_page_request(start_index)
        else:
            self.logger.info("Reached the maximum number of pages to scrape")

    def parse_vulnerability_details(self, response):
        vuln_id = response.meta['vuln_id']
        published_date = response.meta['published_date']
        title = response.meta['title']
        self.logger.info(f"Parsing details for vulnerability: {vuln_id}")
        
        severity = response.css("div#severitycirclecontent::text").get()
        release_date = response.css("div.divLabelContent:contains('First Published')::text").get()
        summary = response.css("div#summaryfield ::text").getall()
        summary = ' '.join(summary).strip()
        
        affected_products = []
        product_table = response.css("table#affproducts")
        if product_table:
            rows = product_table.css("tbody tr")
            for row in rows:
                product = row.css("td:nth-child(1)::text").get().strip()
                affected_products.append(product)
        
        recommendations = response.css("div#fixedsoftfield").get()
        if recommendations:
            recommendations = re.sub('<[^<]+?>', '', recommendations).strip()
        
        result = {
            'cve_id': vuln_id,
            'title': title,
            'published_date': published_date,
            'description': "Cisco",
            'org_link': response.url,
            'release_date': release_date,
            'severity': severity,
            'summary': summary,
            'affected_products': affected_products,
            'recommendations': recommendations
        }
        
        self.results.append(result)

    def errback_httpbin(self, failure):
        self.logger.error(f"Error on {failure.request.url}: {str(failure.value)}")

    def closed(self, reason):
        end_time = datetime.now()
        duration = end_time - self.start_time
        self.logger.info(f"Total time taken: {duration.total_seconds():.2f} seconds")
        
        if self.results:
            with open('data/cisco_vulnerabilities.json', 'w') as f:
                json.dump(self.results, f, indent=2)
            self.logger.info(f"Results written to cisco_vulnerabilities.json")
        else:
            self.logger.warning("No results were collected during the scraping process.")

# Run the spider
if __name__ == "__main__":
    from scrapy.crawler import CrawlerProcess
    from scrapy.utils.project import get_project_settings

    process = CrawlerProcess(get_project_settings())
    process.crawl(CiscoVulnerabilitySpider)
    process.start()