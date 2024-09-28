import scrapy
import json
from datetime import datetime
from urllib.parse import urljoin

class AdobeSecurityAdvisorySpider(scrapy.Spider):
    name = 'adobe_security_advisory'
    start_urls = ['https://helpx.adobe.com/in/security/Home.html']
    
    def __init__(self, advisories_to_scrape=10, *args, **kwargs):
        super(AdobeSecurityAdvisorySpider, self).__init__(*args, **kwargs)
        self.items = []
        self.advisories_to_scrape = int(advisories_to_scrape)
        self.advisories_scraped = 0
    
    def parse(self, response):
        table = response.css('table')
        rows = table.css('tr')[1:]  # Skip the header row
        
        for row in rows:
            if self.advisories_scraped < self.advisories_to_scrape:
                columns = row.css('td')
                link = columns[0].css('a::attr(href)').get()
                title = columns[0].css('a::text').get()
                originally_posted = columns[1].css('::text').get().strip()
                last_updated = columns[2].css('::text').get().strip()
                
                full_url = urljoin(response.url, link)
                yield scrapy.Request(url=full_url, callback=self.parse_advisory,
                                     meta={'title': title, 'originally_posted': originally_posted, 'last_updated': last_updated},
                                     errback=self.errback_httpbin)
                self.advisories_scraped += 1
            else:
                break

    def parse_advisory(self, response):
        title = response.meta['title']
        originally_posted = response.meta['originally_posted']
        last_updated = response.meta['last_updated']

        # Extract affected products
        affected_products = []
        product_table = response.css('div.dexter-Table-Container table')[1]
        for row in product_table.css('tbody tr')[1:]:
            product = row.css('td.column-c0 p::text').get()
            version = row.css('td.column-c1 p::text').get()
            if product and version:
                affected_products.append(f"{product.strip()} {version.strip()}")

        # Extract recommendation
        recommendation = ""
        recommendation_table = response.css('div.dexter-Table-Container table')[2]
        recommendations_list = []
        for row in recommendation_table.css('tbody tr')[1:]:
            product = row.css('td.column-c0 p::text').get()
            version = row.css('td.column-c1 p::text').get()
            if product and version:
                recommendations_list.append(f"{product.strip()} {version.strip()}")
        if recommendations_list:
            recommendation = "Update the following products and versions: " + ", ".join(recommendations_list)

        # Extract CVEs and severities
        cve_table = response.css('div.dexter-Table-Container table')[3]
        for row in cve_table.css('tbody tr')[1:]:
            cve = row.css('td:contains("CVE") p::text').get()
            severity = row.css('td.column-c2 p::text').get()

            if cve and severity:
                scraped_item = {
                    'cve_id': cve.strip(),
                    'published_date': self.format_date(originally_posted),
                    'description': 'Adobe',
                    'org_link': response.url,
                    'release_date': self.format_date(last_updated),
                    'severity': severity.strip().capitalize(),
                    'summary': title,
                    'affected_products': affected_products,
                    'recommendations': recommendation
                }
                
                self.items.append(scraped_item)
                yield scraped_item

    def format_date(self, date_string):
        try:
            date_obj = datetime.strptime(date_string.strip(), "%B %d, %Y")
            return date_obj.strftime("%d/%m/%Y")
        except ValueError:
            return date_string

    def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure}")

    def closed(self, reason):
        with open('data/adobe_security_advisory_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to adobe_security_advisory_output.json")