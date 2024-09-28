import os
from scrapy.crawler import CrawlerProcess
from nvd_scraper.spiders.ibm import IBMVulnerabilitySpider
from nvd_scraper.spiders.qnap import QNAPAdvisorySpider
from nvd_scraper.spiders.wordfence import WordFenceVulnerabilitySpider
from nvd_scraper.spiders.microsoft import MicrosoftVulnerabilitySpider
from nvd_scraper.spiders.cisco import CiscoAdvisorySpider
from nvd_scraper.spiders.firefox import MozillaSecurityAdvisorySpider  
from nvd_scraper.spiders.adobe_security_spider import AdobeSecurityAdvisorySpider

def run_second_level_scraping():
    process = CrawlerProcess()
    process.crawl(IBMVulnerabilitySpider)
    process.crawl(QNAPAdvisorySpider)
    process.crawl(WordFenceVulnerabilitySpider)
    process.crawl(MicrosoftVulnerabilitySpider)
    process.crawl(CiscoAdvisorySpider)
    process.crawl(MozillaSecurityAdvisorySpider)
    process.crawl(AdobeSecurityAdvisorySpider)
    process.start()

if __name__ == "__main__":
    run_second_level_scraping()