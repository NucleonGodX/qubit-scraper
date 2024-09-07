import scrapy
from scrapy.http import Request
from urllib.parse import urlencode
from datetime import datetime
import logging
import json

class NVDSpider(scrapy.Spider):
    name = 'nvd_spider'
    allowed_domains = ['nvd.nist.gov']
    base_url = 'https://nvd.nist.gov/vuln/search/results'
    
    def __init__(self, *args, **kwargs):
        super(NVDSpider, self).__init__(*args, **kwargs)
        self.start_time = datetime.now()
        logging.getLogger('scrapy').setLevel(logging.INFO)
        self.logger.setLevel(logging.INFO)
        self.results = []
        self.page_count = 0  # Counter for the number of pages scraped
        self.max_pages = 10  # Limit the number of pages to scrape

    def start_requests(self):
        # Start from page 1 (startIndex=0)
        yield self.get_page_request(0)

    def get_page_request(self, start_index):
        params = {
            'isCpeNameSearch': 'false',
            'results_type': 'overview',
            'form_type': 'Basic',
            'search_type': 'last3months',
            'startIndex': start_index
        }
        url = f"{self.base_url}?{urlencode(params)}"
        return Request(url, self.parse_search_results, meta={'start_index': start_index})

    def parse_search_results(self, response):
        self.logger.info(f"Parsing search results from: {response.url}")
        cve_rows = response.css("tbody tr")
        self.logger.info(f"Found {len(cve_rows)} CVE rows on this page")
        
        for row in cve_rows:
            cve_link = row.css("a[data-testid^='vuln-detail-link-']")
            if cve_link:
                cve_id = cve_link.css("::text").get().strip()
                cve_url = response.urljoin(cve_link.attrib['href'])
                published_date = row.css("span[data-testid^='vuln-published-on']::text").get()
                if published_date:
                    published_date = published_date.strip()
                self.logger.info(f"Found CVE: {cve_id}, Published: {published_date}")
                yield Request(cve_url, self.parse_cve_details, meta={
                    'cve_id': cve_id,
                    'published_date': published_date
                })
        
        self.page_count += 1  # Increment the page counter

        # Continue scraping the next page if the maximum page limit is not reached
        if self.page_count < self.max_pages:
            start_index = response.meta['start_index'] + 20  # Move to the next page
            yield self.get_page_request(start_index)
        else:
            self.logger.info("Reached the maximum number of pages to scrape")

    def parse_cve_details(self, response):
        cve_id = response.meta['cve_id']
        published_date = response.meta['published_date']
        self.logger.info(f"Parsing details for CVE: {cve_id}")
        
        # Extract the description source
        description_source = response.css("span[data-testid='vuln-current-description-source']::text").get()
        if description_source:
            description_source = description_source.strip()
        self.logger.info(f"Description source for {cve_id}: {description_source}")
        
        selectors = [
            'a.external[target="_blank"][rel="noopener noreferrer"]::attr(href)',
            'a[target="_blank"][rel="noopener noreferrer"]::attr(href)',
            'a[class*="external"]::attr(href)',
            'a[href^="http"]::attr(href)'
        ]
        
        external_links = []
        for selector in selectors:
            links = response.css(selector).getall()
            if links:
                external_links.extend(links)
        
        org_link = next((link for link in external_links if 'qnap' in link.lower() or 'ibm' in link.lower() or 'wordfence' in link.lower() or 'kernel' in link.lower() or 'wpscan' in link.lower() or 'adobe' in link.lower() or 'freebsd' in link.lower() or "indico/security" in link.lower()), None)
        
        if org_link:
            self.logger.info(f"Found QNAP/IBM/Wordfence link for {cve_id}: {org_link}")
            result = {
                'cve_id': cve_id,
                'published_date': published_date,
                'description_source': description_source,
                'org_link': org_link
            }
            self.results.append(result)
        else:
            self.logger.info(f"No QNAP/IBM/Wordfence link found for {cve_id}")

    def closed(self, reason):
        end_time = datetime.now()
        duration = end_time - self.start_time
        self.logger.info(f"Total time taken: {duration.total_seconds():.2f} seconds")
        
        # Write results to JSON file
        with open('qnap_cves.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results written to qnap_cves.json")

# In settings.py:
# CONCURRENT_REQUESTS = 4
# DOWNLOAD_DELAY = 2
# ROBOTSTXT_OBEY = True
# USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
# HTTPCACHE_ENABLED = False

# To run the spider:
# scrapy runspider nvd_spider.py