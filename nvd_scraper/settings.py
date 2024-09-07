BOT_NAME = "nvd_scraper"

SPIDER_MODULES = ["nvd_scraper.spiders"]
NEWSPIDER_MODULE = "nvd_scraper.spiders"


# Set settings whose default value is deprecated to a future-proof value
REQUEST_FINGERPRINTER_IMPLEMENTATION = "2.7"
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
FEED_EXPORT_ENCODING = "utf-8"

# CONCURRENT_REQUESTS = 4
# DOWNLOAD_DELAY = 2
# ROBOTSTXT_OBEY = True
# USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
# HTTPCACHE_ENABLED = False
# LOG_LEVEL = 'DEBUG'