
import re
import requests
import whois
import tldextract
import dns.resolver

from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

subdomain_extractor = tldextract.TLDExtract()


def extract_basic_features(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]

    features = {}

    # 1. IP address
    features["having_ip_address"] = -1 if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$", domain
    ) else 1

    # 2. URL length
    if len(url) < 54:
        features["url_length"] = 1
    elif len(url) <= 75:
        features["url_length"] = 0
    else:
        features["url_length"] = -1

    # 3. URL shortening service
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
    features["shortining_service"] = -1 if any(
        s in domain.lower() for s in shorteners
    ) else 1

    # 4. @ symbol
    features["having_at_symbol"] = -1 if "@" in url else 1

    # 5. Double slash redirecting
    features["double_slash_redirecting"] = -1 if "//" in url[8:] else 1

    # 6. Prefix suffix
    features["prefix_suffix"] = -1 if "-" in domain else 1

    # 7. Subdomain
    features["having_sub_domain"] = get_correct_subdomain_value(url)

    return features


def get_correct_subdomain_value(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    hostname = urlparse(url).hostname or ""
    result = subdomain_extractor(hostname)

    subdomains = [
        part for part in result.subdomain.split(".")
        if part and part.lower() != "www"
    ]

    if len(subdomains) == 0:
        return 1
    elif len(subdomains) == 1:
        return 0
    else:
        return -1


def extract_ssl_final_state(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
            verify=True
        )

        if urlparse(response.url).scheme.lower() == "https":
            print("HTTPS certificate verification successful.")
            return 1
        else:
            print("Final webpage does not use HTTPS.")
            return -1

    except requests.exceptions.SSLError:
        print("SSL certificate verification failed.")
        return -1

    except Exception as e:
        print("SSL verification unavailable:", e)


def get_domain_registration_length(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = urlparse(url).hostname
        info = whois.whois(domain)

        expiry = info.expiration_date

        if isinstance(expiry, list):
            expiry = expiry[0]

        if expiry is None:
            return None

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        days_left = (
            expiry - datetime.now(timezone.utc)
        ).days

        print("Domain:", domain)
        print("Days until expiry:", days_left)

        return 1 if days_left > 365 else -1

    except Exception as e:
        print("WHOIS lookup unavailable:", e)
        return None


def extract_favicon_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")

        icon_link = soup.find(
            "link",
            rel=lambda value: value and "icon" in str(value).lower()
        )

        if icon_link and icon_link.get("href"):
            favicon_url = urljoin(url, icon_link["href"])
        else:
            favicon_url = urljoin(url, "/favicon.ico")

        website_domain = urlparse(url).hostname
        favicon_domain = urlparse(favicon_url).hostname

        if website_domain == favicon_domain:
            return 1
        else:
            return -1

    except Exception as e:
        print("Favicon extraction unavailable:", e)
        return None


def extract_port_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        port = parsed.port

        if port is None:
            return 1

        if port in [80, 443]:
            return 1
        else:
            return -1

    except Exception as e:
        print("Port extraction error:", e)
        return None


def extract_https_token_feature(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    domain = urlparse(url).hostname or ""

    if "https" in domain.lower():
        return -1
    else:
        return 1


def extract_request_url_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")
        website_domain = urlparse(url).hostname

        resources = []

        for tag in soup.find_all(["img", "audio", "video", "script", "link"]):
            resource = (
                tag.get("src") or
                tag.get("href") or
                tag.get("data-src")
            )

            if resource:
                resources.append(urljoin(url, resource))

        if not resources:
            return None

        external_count = sum(
            1 for resource in resources
            if urlparse(resource).hostname != website_domain
        )

        external_percentage = (external_count / len(resources)) * 100

        if external_percentage < 22:
            return 1
        else:
            return -1

    except Exception as e:
        print("Request URL extraction unavailable:", e)
        return None


def extract_url_of_anchor_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        website_domain = urlparse(response.url).hostname

        anchors = soup.find_all("a", href=True)

        if not anchors:
            return None

        suspicious_count = 0

        for anchor in anchors:
            href = anchor["href"].strip()
            parsed_link = urlparse(urljoin(response.url, href))

            # Anchors that do not lead to a webpage
            if href.startswith("#") or parsed_link.scheme == "javascript":
                suspicious_count += 1

            # Links pointing to another hostname
            elif parsed_link.hostname and parsed_link.hostname != website_domain:
                suspicious_count += 1

        percentage = (suspicious_count / len(anchors)) * 100

        if percentage < 31:
            return 1
        elif percentage <= 67:
            return 0
        else:
            return -1

    except Exception as e:
        print("Anchor URL extraction unavailable:", e)
        return None


def extract_links_in_tags_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        website_domain = urlparse(response.url).hostname

        links = []

        for tag in soup.find_all(["meta", "script", "link"]):
            resource = (
                tag.get("content") if tag.name == "meta"
                else tag.get("src") or tag.get("href")
            )

            if resource:
                links.append(urljoin(response.url, resource))

        if not links:
            return None

        external_count = sum(
            1 for link in links
            if urlparse(link).hostname
            and urlparse(link).hostname != website_domain
        )

        percentage = (external_count / len(links)) * 100

        if percentage < 17:
            return 1
        elif percentage <= 81:
            return 0
        else:
            return -1

    except Exception as e:
        print("Links in tags extraction unavailable:", e)
        return None

        return None


def extract_sfh_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")
        website_domain = urlparse(url).hostname

        forms = soup.find_all("form")

        if not forms:
            return None

        for form in forms:
            action = form.get("action", "").strip()

            if not action:
                return -1

            destination = urljoin(url, action)
            destination_domain = urlparse(destination).hostname

            if destination_domain != website_domain:
                return -1

        return 1

    except Exception as e:
        print("SFH extraction unavailable:", e)
        return None


def extract_submitting_to_email_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action", "").strip().lower()

            if action.startswith("mailto:"):
                return -1

        return 1

    except Exception as e:
        print("Email submission extraction unavailable:", e)
        return None


def extract_redirect_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        redirect_count = len(response.history)

        print("Number of redirects:", redirect_count)

        if redirect_count < 2:
            return 1
        else:
            return 0

    except Exception as e:
        print("Redirect extraction unavailable:", e)
        return None


def extract_on_mouseover_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all(onmouseover=True):
            script = tag.get("onmouseover", "")

            if re.search(r"(window\.)?status\s*=", script, re.I):
                return -1

        return 1

    except Exception as e:
        print("Mouseover extraction unavailable:", e)
        return None


def extract_rightclick_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")

        # Check inline JavaScript
        page_source = response.text.lower()

        if re.search(r"event\.button\s*==\s*2", page_source):
            return -1

        # Check oncontextmenu handlers
        for tag in soup.find_all(oncontextmenu=True):
            script = str(tag.get("oncontextmenu", "")).lower()

            if "return false" in script:
                return -1

        return 1

    except Exception as e:
        print("Right-click extraction unavailable:", e)
        return None


def extract_popup_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")

        # Check JavaScript for popup creation
        for script_tag in soup.find_all("script"):
            script = script_tag.string or script_tag.get_text()

            if re.search(r"window\.open\s*\(", script, re.I):
                return -1

        return 1

    except Exception as e:
        print("Popup feature extraction unavailable:", e)
        return None


def extract_iframe_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        soup = BeautifulSoup(response.text, "html.parser")

        iframes = soup.find_all("iframe")

        for iframe in iframes:
            width = iframe.get("width", "")
            height = iframe.get("height", "")
            style = iframe.get("style", "").lower()

            # Check for hidden or invisible iframe
            if (
                width == "0"
                or height == "0"
                or "display:none" in style.replace(" ", "")
                or "visibility:hidden" in style.replace(" ", "")
            ):
                return -1

        return 1

    except Exception as e:
        print("IFrame feature extraction unavailable:", e)
        return None


def extract_domain_age_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = urlparse(url).hostname

        info = whois.whois(domain)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            print("Domain creation date unavailable")
            return None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        age_days = (
            datetime.now(timezone.utc) - creation_date
        ).days

        print("Domain:", domain)
        print("Domain age in days:", age_days)

        if age_days >= 180:
            return 1
        else:
            return -1

    except Exception as e:
        print("Domain age lookup unavailable:", e)
        return None


def extract_dns_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = urlparse(url).hostname

        dns.resolver.resolve(domain, "A")

        print("Domain:", domain)
        print("DNS record found!")

        return 1

    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return -1

    except Exception as e:
        print("DNS lookup unavailable:", e)
        return None


def extract_web_traffic_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        hostname = urlparse(url).hostname

        extracted = tldextract.extract(hostname)
        domain = extracted.top_domain_under_public_suffix

        if not domain:
            return None

        api_url = f"https://tranco-list.eu/api/ranks/domain/{domain}"

        response = requests.get(api_url, timeout=15)
        response.raise_for_status()

        data = response.json()
        ranks = data.get("ranks", [])

        if not ranks:
            print("No Tranco ranking available")
            return -1

        latest = ranks[-1]
        rank = latest["rank"]

        print("Domain:", domain)
        print("Tranco rank:", rank)

        # Implementation threshold: top 100,000
        if rank <= 100000:
            return 1
        else:
            return -1

    except Exception as e:
        print("Web traffic lookup unavailable:", e)
        return None



available_features = [
    "having_ip_address", "url_length", "shortining_service",
    "having_at_symbol", "double_slash_redirecting", "prefix_suffix",
    "having_sub_domain", "sslfinal_state", "domain_registration_length",
    "favicon", "port", "https_token", "request_url", "url_of_anchor",
    "links_in_tags", "sfh", "submitting_to_email", "redirect",
    "on_mouseover", "rightclick", "popupwindow", "iframe",
    "age_of_domain", "dnsrecord", "web_traffic"
]

feature_extractors = {
    "sslfinal_state": extract_ssl_final_state,
    "domain_registration_length": get_domain_registration_length,
    "favicon": extract_favicon_feature,
    "port": extract_port_feature,
    "https_token": extract_https_token_feature,
    "request_url": extract_request_url_feature,
    "url_of_anchor": extract_url_of_anchor_feature,
    "links_in_tags": extract_links_in_tags_feature,
    "sfh": extract_sfh_feature,
    "submitting_to_email": extract_submitting_to_email_feature,
    "redirect": extract_redirect_feature,
    "on_mouseover": extract_on_mouseover_feature,
    "rightclick": extract_rightclick_feature,
    "popupwindow": extract_popup_feature,
    "iframe": extract_iframe_feature,
    "age_of_domain": extract_domain_age_feature,
    "dnsrecord": extract_dns_feature,
    "web_traffic": extract_web_traffic_feature
}

def collect_live_features_25(url):
    features = extract_basic_features(url)

    for feature_name, extractor in feature_extractors.items():
        try:
            features[feature_name] = extractor(url)
        except Exception as e:
            print(feature_name, "extraction failed:", e)
            features[feature_name] = None

    return {name: features.get(name) for name in available_features}
