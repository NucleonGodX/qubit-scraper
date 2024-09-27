import scrapy
from scrapy.http import HtmlResponse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import json
from datetime import datetime

class MicrosoftVulnerabilitySpider(scrapy.Spider):
    name = 'microsoft_vulnerability'
    
    def __init__(self, *args, **kwargs):
        super(MicrosoftVulnerabilitySpider, self).__init__(*args, **kwargs)
        self.items = []
        
        # Set up Selenium
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--window-size=1920,1080")
        self.driver = webdriver.Chrome(options=chrome_options)
    
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
            if 'microsoft.com' in item.get('org_link', '').lower():
                yield scrapy.Request(url=item['org_link'], callback=self.parse, meta={'item': item}, dont_filter=True)
                request_count += 1
        
        self.logger.info(f"Generated {request_count} requests")

    def parse(self, response):
        item = response.meta['item']
        self.driver.get(response.url)
        
        # Wait for multiple elements to be present
        try:
            WebDriverWait(self.driver, 60).until(
                EC.all_of(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "h1.ms-fontWeight-semibold")),
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div.ms-Stack")),
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div[data-automation-key='product']"))
                )
            )
        except Exception as e:
            self.logger.error(f"Timeout waiting for page to load: {response.url}. Error: {str(e)}")
            return
        
        # Additional wait to ensure dynamic content is loaded
        self.driver.implicitly_wait(10)
        
        # Get the page source after JavaScript has rendered the content
        page_source = self.driver.page_source
        sel_response = HtmlResponse(url=response.url, body=page_source, encoding='utf-8')
        
        # Extract summary
        summary = self.safe_extract(sel_response, 'h1.ms-fontWeight-semibold::text')
        self.logger.info(f"Extracted summary: {summary}")
        
        # Extract severity
        severity = self.safe_extract(sel_response, 'div.ms-Stack p:contains("Max Severity:")::text', method='re_first', pattern=r'Max Severity:\s*(\w+)')
        self.logger.info(f"Extracted severity: {severity}")
        
        # Extract affected products
        affected_products = sel_response.css('div[data-automation-key="product"]::text').getall()
        affected_products = [f"{product.strip()}" for product in affected_products if product.strip()]
        self.logger.info(f"Extracted affected products: {affected_products}")
        
        # Extract recommendations
        recommendations = self.safe_extract(sel_response, 'div.root-144::text')
        
        # Convert published_date to dd/mm/yyyy format
        published_date = item.get('published_date')
        formatted_date = self.format_date(published_date)
        
        scraped_item = {
            'cve_id': item.get('cve_id'),
            'published_date': formatted_date,
            'description': "Microsoft",
            'org_link': response.url,
            'release_date': formatted_date,
            'severity': severity,
            'summary': summary,
            'affected_products': affected_products,
            'recommendations': recommendations
        }
        
        self.items.append(scraped_item)
        self.logger.info(f"Scraped item for CVE-ID: {scraped_item['cve_id']}")
        yield scraped_item

    def safe_extract(self, response, selector, method='get', pattern=None):
        try:
            if method == 'get':
                result = response.css(selector).get()
            elif method == 're_first':
                result = response.css(selector).re_first(pattern)
            else:
                self.logger.error(f"Unknown extraction method: {method}")
                return None
            
            return result.strip() if result else None
        except Exception as e:
            self.logger.error(f"Error extracting with selector '{selector}': {str(e)}")
            return None

    def format_date(self, date_string):
        try:
            date_object = datetime.strptime(date_string, "%Y-%m-%d")
            return date_object.strftime("%d/%m/%Y")
        except ValueError:
            self.logger.error(f"Error parsing date: {date_string}")
            return date_string

    def closed(self, reason):
        self.driver.quit()
        with open('data/microsoft_vulnerabilities_output.json', 'w') as f:
            json.dump(self.items, f, indent=2)
        self.logger.info(f"Spider closed. Wrote {len(self.items)} items to microsoft_vulnerabilities_output.json")