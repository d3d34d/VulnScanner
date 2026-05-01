import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger("VulnScanner")

class WebCrawler:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.forms = []
        self.session = requests.Session()
        # Set a standard user-agent
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

    def extract_forms(self, url, html):
        soup = BeautifulSoup(html, "html.parser")
        page_forms = soup.find_all("form")
        for form in page_forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                if input_name:
                    inputs.append({"name": input_name, "type": input_type})
            
            form_url = urljoin(url, action) if action else url
            self.forms.append({
                "url": form_url,
                "method": method,
                "inputs": inputs
            })
            logger.debug(f"Found form on {url} pointing to {form_url}")

    def get_links(self, url, html):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href")
            full_url = urljoin(url, href)
            # Only crawl the same domain
            if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                # Remove fragments
                full_url = full_url.split("#")[0]
                links.add(full_url)
        return links

    def crawl(self):
        urls_to_visit = [(self.base_url, 0)]
        
        while urls_to_visit:
            url, depth = urls_to_visit.pop(0)
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
                
            self.visited_urls.add(url)
            logger.info(f"Crawling: {url}")
            
            try:
                response = self.session.get(url, timeout=5)
                if "text/html" in response.headers.get("Content-Type", ""):
                    self.extract_forms(url, response.text)
                    
                    if depth < self.max_depth:
                        new_links = self.get_links(url, response.text)
                        for link in new_links:
                            if link not in self.visited_urls:
                                urls_to_visit.append((link, depth + 1))
            except requests.RequestException as e:
                logger.debug(f"Failed to crawl {url}: {e}")
                
        return self.visited_urls, self.forms
