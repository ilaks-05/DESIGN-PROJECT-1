import ipaddress
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import whois
from datetime import date


class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = urlparse(url)
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.RequestException:
            self.response = None
            self.soup = None

        try:
            self.domain = self.urlparse.netloc
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        shorteners = (
            "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "bit.do", "cutt.ly", "is.gd", "v.gd", "shorte.st"
        )
        if any(shortener in self.url for shortener in shorteners):
            return -1
        return 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.find("//", 7) != -1 else 1

    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    def SubDomains(self):
        subdomains = self.domain.split(".")
        if len(subdomains) <= 2:
            return 1
        elif len(subdomains) == 3:
            return 0
        return -1

    def Hppts(self):
        return 1 if self.urlparse.scheme == "https" else -1

    def DomainRegLen(self):
        try:
            if self.whois_response and self.whois_response.expiration_date:
                expiration_date = (
                    self.whois_response.expiration_date[0]
                    if isinstance(self.whois_response.expiration_date, list)
                    else self.whois_response.expiration_date
                )
                if expiration_date:
                    reg_length = (expiration_date - date.today()).days
                    return 1 if reg_length >= 365 else -1
        except:
            pass
        return 0  # Treat missing registration length as neutral

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', rel="icon", href=True):
                if self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    def RequestURL(self):
        try:
            total = len(self.soup.find_all(["img", "audio", "embed", "iframe"], src=True))
            external = sum(1 for tag in self.soup.find_all(["img", "audio", "embed", "iframe"], src=True)
                           if self.domain not in tag['src'])
            percentage = (external / total) * 100 if total else 0
            if percentage < 22:
                return 1
            elif percentage <= 61:
                return 0
            return -1
        except:
            return -1

    def AnchorURL(self):
        try:
            total = len(self.soup.find_all('a', href=True))
            unsafe = sum(1 for a in self.soup.find_all('a', href=True)
                         if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower())
            percentage = (unsafe / total) * 100 if total else 0
            if percentage < 31:
                return 1
            elif percentage <= 67:
                return 0
            return -1
        except:
            return -1

    def getFeaturesList(self):
        return [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Hppts(),
            self.DomainRegLen(),
            self.Favicon(),
            self.RequestURL(),
            self.AnchorURL(),
        ]

    def classify(self):
        # Feature weights based on importance
        feature_weights = [2, 1, 3, 1, 1, 1, 1, 3, 2, 2, 2, 1]
        features = self.getFeaturesList()

        # Replace None values with neutral score (0)
        features = [0 if f is None else f for f in features]

        # Calculate weighted score
        score = sum(f * w for f, w in zip(features, feature_weights))

        # Threshold for classification
        return "Phishing" if score < 0 else "Not Phishing"


if __name__ == "__main__":
    # Test URLs
    urls = [
        "http://bit.ly/fake-google-login",  # Phishing
        "https://mail.google.com",  # Legitimate
        "http://bit.ly/fake-facebook-login",
        "http://bit.ly/fake-instagram-login"
    ]

    for url in urls:
        features = FeatureExtraction(url)
        print(f"URL: {url}")
        print(f"Features: {features.getFeaturesList()}")
        print(f"Classification: {features.classify()}")
        print("-" * 50)
