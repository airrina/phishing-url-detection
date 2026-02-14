# Phishing URL Detector

## What is this program?
A Python tool that analyzes URLs and detects potential phishing indicators.
The program assigns a risk score based on multiple checks and returns a verdict.

## How to run
```bash
python phishing_detector.py
```

## What the program detects
- Suspicious words in the URL (login, verify, account...)
- IP address instead of a domain name
- Suspicious top-level domains (.xyz, .tk, .ru...)
- Known brand names (paypal, microsoft, chase...)
- Typosquatting using SequenceMatcher (paypa1 → paypal)

## Risk score
- 0 = Safe
- 1-2 = Suspicious
- 3-4 = Likely phishing
- 5-6 = Dangerous
- 7+ = Highly dangerous

## Example output
```
Enter the URL to analyze: http://micros0ft-login.com/account/verify
Suspicious word found: login
domain is similar to a common brand: microsoft (0.89)
The URL is a phishing attempt with a score of 5, and is dangerous.
## Note
You can easily extend the lists of suspicious words, 
TLDs and brand names directly in the source code.
