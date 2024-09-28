import scrapy
import json
from w3lib.html import remove_tags
from datetime import datetime
from urllib.parse import urljoin

class MozillaSecurityAdvisorySpider(scrapy.Spider):
    name = 'mozilla_security_advisory'
    start_urls = ['https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/']
    
    def __init__(self, versions_to_scrape=1, *args, **kwargs):
        super(MozillaSecurityAdvisorySpider, self).__init__(*args, **kwargs)
        self.items = []
        self.versions_to_scrape = int(versions_to_scrape)
        self.versions_scraped = 0
    
    def parse(self, response):
        version_links = response.css('li.level-item a::attr(href)').getall()
        for link in version_links:
            if self.versions_scraped < self.versions_to_scrape:
                full_url = urljoin(response.url, link)
                self.logger.info(f"Scraping advisory link: {full_url}")
                yield scrapy.Request(url=full_url, callback=self.parse_advisory, errback=self.errback_httpbin)
                self.versions_scraped += 1
            else:
                break

    def parse_advisory(self, response):
        self.logger.info(f"Parsing advisory from {response.url}")

        announced_date = response.css('dl.summary dd::text').get()
        if announced_date:
            announced_date = announced_date.strip()
        fixed_in = response.css('dt:contains("Fixed in") + dd li::text').get()
        if fixed_in:
            fixed_in = fixed_in.strip()
        affected_product = "Firefox"
        affected_versions = f"Versions before {fixed_in}" if fixed_in else "Unknown"

        cve_sections = response.css('section.cve')
        
        for cve_section in cve_sections:
            cve_id = cve_section.css('h4::attr(id)').get()
            summary = cve_section.css('h4 a::text').get()
            if summary:
                summary = summary.strip()
            description = cve_section.css('h5 + p::text').get()
            if description:
                description = description.strip()
            severity = cve_section.css('span.level::text').get()
            if severity:
                severity = severity.strip()

            scraped_item = {
                'cve_id': cve_id,
                'published_date': self.format_date(announced_date) if announced_date else None,
                'description': 'Firefox',
                'org_link': response.url,
                'release_date': self.format_date(announced_date) if announced_date else None,
                'severity': severity.capitalize() if severity else "Unknown",
                'summary': description or "No summary available",
                'affected_products': [
                    f"{affected_product} version: {affected_versions}"
                ],
                'recommendations': f"Update to {fixed_in} or later" if fixed_in else "Update to the latest version"
            }
            
            self.items.append(scraped_item)
            self.logger.info(f"Scraped item for CVE-ID: {scraped_item['cve_id']}")
            yield scraped_item

    def format_date(self, date_string):
        if not date_string:
            return None
        try:
            # First, try to parse the input date string as "September 03, 2024; 12:00:00 AM -0400"
            date_obj = datetime.strptime(date_string.strip(), "%B %d, %Y; %I:%M:%S %p -0400")
            return date_obj.strftime("%d/%m/%Y")
        except ValueError:
            try:
                # If that fails, try to parse it as "%B %d, %Y"
                date_obj = datetime.strptime(date_string.strip(), "%B %d, %Y")
                return date_obj.strftime("%d/%m/%Y")
            except ValueError:
                return date_string  # Return the original string if parsing fails

    def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure}")

    def closed(self, reason):
        with open('data/mozilla_security_advisory_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to mozilla_security_advisory_output.json")