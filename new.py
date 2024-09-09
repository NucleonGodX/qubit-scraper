import os
from scrapy.crawler import CrawlerProcess
from nvd_scraper.spiders.ibm import IBMVulnerabilitySpider
from nvd_scraper.spiders.qnap import QNAPAdvisorySpider
from nvd_scraper.spiders.wordfence import WordFenceVulnerabilitySpider

def run_second_level_scraping():
    process = CrawlerProcess()
    process.crawl(IBMVulnerabilitySpider)
    process.crawl(QNAPAdvisorySpider)
    process.crawl(WordFenceVulnerabilitySpider)
    process.start()

if __name__ == "__main__":
    run_second_level_scraping()