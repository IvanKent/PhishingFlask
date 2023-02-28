from flask import Flask, render_template, request
import joblib
import pandas as pd

import ipaddress as ipAdd
import re
import urllib.parse
from urllib.parse import urlparse, urlencode, urljoin
import whois
from datetime import datetime
import datetime
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

model = joblib.load('XGBoost(70-30).pickle.dat')

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        url = request.form['url']
        features = extract_features(url)
        prediction = model.predict(features.reshape(1, -1))  # Reshape features to 2D array
        return render_template('result.html', prediction=prediction[0])
    else:
        return render_template('index.html')

        
    

def extract_features(url):
    features = []
    # Extract features using regular expressions and string manipulation
    # Address Bar Based Features (9)
    features.append(check_Hex_IP(url))
    features.append(check_URL_Length(url))
    features.append(shortening_Services_URL(url))
    features.append(at_Sign_URL(url))
    features.append(redirection(url))
    features.append(have_Prefix_Suffix_URL(url))
    features.append(check_domain_registration_length(url))
    features.append(check_favicon_domain(url))
    features.append(have_http_Domain_URL(url))

    # Abnormal Based Features(4)
    features.append(check_external_objects(url))
    features.append(check_URL_anchor(url))
    features.append(check_tags(url))
    features.append(check_sfh(url))

    # HTML and Javascript Features(5)
    try:
        response = requests.get(url)
    except:
        response = ""
    features.append(check_Redirection(url))
    features.append(check_onmouseover(url))
    features.append(check_right_click(url))
    features.append(check_popup_window(url))
    features.append(check_iframe(url))

    # DOMAIN BASED FEATURES (4)
    features.append(check_url_age(url))
    features.append(check_dns_record(url))
    features.append(no_pointing_links(url))
    features.append(check_domain_expiration(url))

    # Convert features to a pandas DataFrame
    df = pd.DataFrame([features], columns=['IP', 'URL Length', 'ShortURL', 'atSign', 'redirection', 'Prefix/Suffix', 'registrationLength', 'favicon', 'https',
                   'objects', 'anchor', 'tags', 'sfh',
                    'forwarding','statusBar','rightClick', 'popUp', 'IFrame',
                    'url Age', 'DNS Record', 'Pointing Links', 'Expiration'])

    # Convert the DataFrame to a 2D NumPy array
    X = df.to_numpy()

    return X


#features

#Feature(1.1.1) that checks if the URL has IP
def check_Hex_IP(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return 1
        
        hex_regex = r"\b0x[\da-f]{1,8}\b"
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for match in re.findall(hex_regex, response.text, re.IGNORECASE):
            if re.search(ip_regex, str(int(match, 16))):
                return 1
        return 0
    except:
        return 1

#Feature(1.1.2) that check the length of URL
#working properly
def check_URL_Length(url):
    if len(url) >= 54:
        length = 1
    else:
        length = 0
    return length

#Feature(1.1.3) that checks if the URL used a URL shortening Services
#working properly

#listing Known URL shortening services
shorteningServices = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

#Function
def shortening_Services_URL(url):
    match=re.search(shorteningServices,url)
    if match:
        return 1
    else:
        return 0


#Feature(1.1.4) that checks if the URl has "@" symbol
#working properly
def at_Sign_URL(url):
    if "@" in url:
        atsymbol = 1    
    else:
        atsymbol = 0    
    return atsymbol

#Feature(1.1.5) that checks if the URL used Redirection "//"
#working properly but might not be reliable
def redirection(url):
    position = url.rfind('//')
    if position > 6:
        if position > 7:
            return 1
        else:
            return 0
    else:
        return 0

#Feature(1.1.6) that checks if the URL has a preffix or Suffix separated by "-" to the Domain
#working properly
def have_Prefix_Suffix_URL(url):
    if '-' in urlparse(url).netloc:
        return 1
    else:
        return 0

#Feature(1.1.9) that checks the registration length of URL
#working
def check_domain_registration_length(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        domain_info = whois.whois(domain)
        expiration_date = domain_info.get("expiration_date")
        if isinstance(expiration_date, datetime.datetime):
            current_date = datetime.datetime.now().date()
            if (expiration_date.date() - current_date).days <= 365:
                return 1
            else:
                return 0
        else:
            return 0
    except Exception:
        # Return 1 if there was an error retrieving the domain registration information
        return 1


#Feature(1.1.10) that checks if the URL uses a favicon from different Domain
#working but not accurate
#subject to changes
def check_favicon_domain(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return -1

    soup = BeautifulSoup(response.content, "html.parser")
    link_tags = soup.find_all("link", rel="icon")
    for tag in link_tags:
        icon_url = tag.get("href")
        if not icon_url.startswith(url):
            return 1
    return 0


#Feature(1.1.12) that checks if the URL used "https" in Domain Name (prototype)
#working but not reliable
def have_http_Domain_URL(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0


#Feature(1.2.1) that checks the object requests in URL
#working
def check_external_objects(url):
    try:
        base_domain = urlparse(url).netloc
        resp = requests.get(url)
        if not resp.ok:
            return 1
        soup = BeautifulSoup(resp.content, 'html.parser')
        tags = ['img', 'audio', 'video']
        count = 0
        external_count = 0
        for tag in tags:
            for item in soup.find_all(tag):
                count += 1
                if item.has_attr('src'):
                    parsed_src = urlparse(item['src'])
                    if parsed_src.netloc != '' and parsed_src.netloc != base_domain:
                        external_count += 1
        if count == 0:
            return 0
        else:
            percent = external_count / count * 100
            if percent < 22:
                return 0
            elif percent >= 22 and percent <= 61:
                return -1
            else:
                return 1
    except RequestException:
        return 1
    
#Feature(1.2.2) that checks if the URL has anchor
#working
def check_URL_anchor(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        base_domain = urlparse(url).netloc
        total_links = 0
        legitimate_links = 0
        suspicious_links = 0
        phishing_links = 0
        for link in soup.find_all('a'):
            total_links += 1
            href = link.get('href')
            parsed_href = urlparse(href)
            if parsed_href.netloc != '' and parsed_href.netloc != base_domain:
                continue  # External links are ignored
            anchor_url_ratio = len(href) / len(url)
            if anchor_url_ratio < 0.31:
                phishing_links += 1
            elif 0.31 <= anchor_url_ratio <= 0.67:
                suspicious_links += 1
            else:
                legitimate_links += 1
        if legitimate_links / total_links >= 0.9:
            return 0
        elif phishing_links / total_links >= 0.2:
            return 1
        else:
            return -1
    except:
        return 1

#Feature(1.2.3) that checks the tags in URL
#working but not reliable
def check_tags(url):
    try:
        resp = requests.get(url)
        if not resp.ok:
            return "1"
        soup = BeautifulSoup(resp.content, 'html.parser')
        tags = ['meta', 'script', 'link']
        count = 0
        internal_count = 0
        for tag in tags:
            for item in soup.find_all(tag):
                count += 1
                if tag == 'meta' and item.has_attr('http-equiv') and item['http-equiv'].lower() == 'refresh':
                    return 1
                if item.has_attr('src') or item.has_attr('href'):
                    parsed = urlparse(item['src'] if item.has_attr('src') else item['href'])
                    if parsed.netloc == '' or parsed.netloc == urlparse(url).netloc:
                        internal_count += 1
        if count == 0:
            return 1
        else:
            percent = internal_count / count * 100
            if percent < 17:
                return 1
            elif percent >= 17 and percent <= 81:
                return -1
            else:
                return 0
    except:
        return 1
    

    #Feature(1.2.4) that checks if the SFH of URL
#might work
def check_sfh(url):
    try:
        resp = requests.get(url)
    except:
        return 1

    if not resp.ok:
        return 1

    soup = BeautifulSoup(resp.content, 'html.parser')
    samesite = urlparse(url).netloc

    for form in soup.find_all('form'):
        sfh = form.get('action')
        if sfh is None or sfh == "" or sfh == "about:blank":
            return 1
        else:
            parsed_sfh = urlparse(sfh)
            if parsed_sfh.netloc != '' and parsed_sfh.netloc != samesite:
                return -1

    return 0


#Feature(1.3.1) that checks the n-times a URL/website have been forwarded
#might work/still not tried
def check_Redirection(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code == 301 or response.status_code == 302:
            num_redirections = 1
            while 'Location' in response.headers:
                response = requests.get(response.headers['Location'], allow_redirects=False)
                num_redirections += 1
            if num_redirections <= 1:
                return 0
            elif num_redirections >= 2 and num_redirections < 4:
                return -1
            else:
                return 1
        else:
            return 0
    except:
        return 1
    
#Feature(1.3.2) that checks the Status Bar Customization
#might work
def check_onmouseover(url):
    try:
        # Get the webpage source code
        response = requests.get(url)
        source_code = response.text

        # Check for onMouseOver event
        pattern = r"onMouseOver\s*=\s*['\"]window\.status\s*=\s*[^'\"]+['\"]"
        if re.search(pattern, source_code, re.IGNORECASE):
            return 1
        else:
            return 0
    except:
        # Return 1 if the URL is invalid or cannot be accessed
        return 1
    
#Feature(1.3.3) that checks if the URL disabled the right click attribute
#might work
def check_right_click(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if 'event.button ?== ?2' in script.text:
                return 1
        return 0
    except requests.exceptions.RequestException:
        return 1
    
#Feature(1.3.4) that checks the Pop-ups of the URL
#might work
def check_popup_window(url):
    try:
        # Send a request to the URL
        response = requests.get(url)

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all pop-up windows on the page
        popups = soup.find_all('div', class_='popup-window')

        # Check if any of the pop-ups contain text fields
        for popup in popups:
            if popup.find('input', type='text') is not None:
                return 1
        
        # If no pop-up window contains text fields, the website is legitimate
        return 0
    except:
        # If there is an error accessing the URL, consider it a phishing attempt
        return 1
    

#Feature(1.3.5) that checks the IFrame Direction
#might work
def check_iframe(url):
    try:
        response = requests.get(url)
        response_text = response.text
        response_string = str(response_text)
        pattern = r"<iframe"
        if re.search(pattern, response_string, re.IGNORECASE):
            invisible_pattern = r"frameborder"
            if not re.search(invisible_pattern, response_string, re.IGNORECASE):
                return 1
            else:
                response_string = re.sub(invisible_pattern, "", response_string)
                response_text = re.sub(invisible_pattern, "", response_text)
                return 1
        else:
            return 0
    except:
        return 1

#Feature(1.4.1) that checks the age of the URL Domain
#working
def check_url_age(url):
    try:
        domain = whois.whois(url)
        if not domain.status:
            # If the domain is invalid or doesn't respond, return 1
            return 1
        else:
            creation_date = domain.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]
            age_in_days = (datetime.datetime.now() - creation_date).days
            if age_in_days >= 180:
                # If age of domain is greater than or equal to 6 months, return 0
                return 0
            else:
                return 1
    except Exception:
        return 1
    
#Feature(1.4.2) that checks the URL's DNS Record
#working
def check_dns_record(url):
    try:
        domain = whois.whois(url)
        if not domain.name_servers:
            # If the DNS record is empty, return 1
            return 1
        else:
            # If the DNS record is not empty, return 0
            return 0
    except Exception:
        # If the domain is invalid or doesn't respond, return 1
        return 1
    
#Feature(1.4.6) that checks the number of links pointing to the page
#Working
def no_pointing_links(url):
    try:
        # Make a request to the webpage
        response = requests.get(url)
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        # Find all external links in the HTML content
        external_links = [link.get('href') for link in soup.find_all('a') if link.get('href').startswith('http') and not url in link.get('href')]
        # Count the number of external links
        num_external_links = len(external_links)
        # Classify the webpage based on the number of external links
        if num_external_links == 0:
            return 1
        elif num_external_links > 0 and num_external_links <= 2:
            return -1
        else:
            return 0
    except:
        # If an exception occurs while making the request, return "Phishing"
        return 1
    

#Feature(1.4.8) that checks the End Period the URL's Domain
#working
def check_domain_expiration(url):
    try:
        domain = whois.whois(url)
        expiration_date = domain.expiration_date
        if expiration_date is None:
            return 1
        if type(expiration_date) is list:
            expiration_date = expiration_date[0]
        remaining_time = expiration_date - datetime.datetime.now()
        if remaining_time.days < 180:
            return 1
        else:
            return 0
    except (whois.parser.PywhoisError, requests.exceptions.RequestException):
        return 1
    

    
