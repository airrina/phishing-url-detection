from urllib.parse import urlparse
import re
from difflib import SequenceMatcher

##score for the url
score = 0

#url to by analyzed
url = input("Enter the URL to analyze: ")
parsed = urlparse(url)

#list od suspicious top level domains
suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site", ".info", ".biz", ".ru", ".cn"]

#ip pattern to check if the url contains an ip address instead of a domain name
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

#list of brands everyone knows that are commonly used in phishing attacks
common_brands = ["microsoft", "paypal", "bankofamerica", "wellsfargo", "chase", "citibank", "americanexpress", "discover", "capitalone", "usbank", "barclays", "hsbc", "tdbank", "ally", "pnc", "suntrust", "bbt", "fifththird", "keybank", "m&tbank", "regionsbank", "usbancorp"]

#list of suspicious words commonly used in phishing urls
suspicious_words = ["paypal", "secure", "login", "account", "verify", "update", "password", "bank", "credit", "card", "ssn", "chase", ]

# Check if the domain contains "paypal"
print("whole URL:", url)
print("domain:", parsed.netloc)
print("Path:", parsed.path)


#list of domain parts
domain_parts = parsed.netloc.lower().split(".")[0].split("-")
print(domain_parts)

#checking if the url has the suspicious words
for word in suspicious_words:
    if word in url.lower():
        score += 1
        print(f"Suspicious word found: {word}")

#checking if the url contains an ip address
if re.search(ip_pattern, url):
    score += 2
    print("The URL contains an IP address.")

#checking if the url has a suspicious top level domain
for tld in suspicious_tlds:
    if parsed.netloc.endswith(tld):
        score += 1
        print(f"Suspicious top-level domain found: {tld}")


#chekc if the url has a common brand name in it
for part in domain_parts:
    for brand in common_brands:
        similarity = SequenceMatcher(None, part, brand).ratio()
        if similarity >= 0.8:
            score += 2
            print(f"domain is similar to a common brand: {brand} with similarity score of {similarity:.2f}")

# check teh score and print the result
if score == 0:
    print(f"the URL is safe with a score of {score}.")
elif score >= 1 and score <= 2:
        print(f"The URL is suspicious with a score of {score}.")
elif score >= 2 and score <= 4:
    print(f"The URL is likely a phishing attempt with a score of {score}.")
elif score >= 4 and score <= 6:
    print(f"The URL is a phishing attempt with a score of {score}, and is dangerous.")
else:
    print(f"The URL is a phishing attempt with a score of {score}, and is highly dangerous.")
