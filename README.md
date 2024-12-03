HOW TO RUN THE PROJECT 
1.Initialization and URL Parsing 
2. Feature Extraction  
UsingIp: 
Checks if the URL contains an IP address. 
Phishing (-1) if IP address is used, Legitimate (1) otherwise. 
longUrl: 
Measures the length of the URL. 
Legitimate (1) for short URLs (<54 characters). 
Suspicious (0) for medium-length (54-75). 
Phishing (-1) for long URLs (>75). 
shortUrl: 
Checks for known URL shorteners (e.g., bit.ly, goo.gl). 
Phishing (-1) if detected, Legitimate (1) otherwise. 
symbol: 
Verifies the presence of @ symbol in the URL. 
Phishing (-1) if present, Legitimate (1) otherwise. 
redirecting: 
Checks for multiple // after the protocol. 
Phishing (-1) if more than one, Legitimate (1) otherwise. 
prefixSuffix: 
Detects hyphens (-) in the domain. 
Phishing (-1) if present, Legitimate (1) otherwise. 
SubDomains: 
Counts the number of subdomains. 
Legitimate (1) for <= 2 subdomains. 
Suspicious (0) for 3 subdomains. 
Phishing (-1) for more than 3 subdomains. 
Hppts: 
Verifies if the URL uses HTTPS. 
Legitimate (1) for HTTPS, Phishing (-1) otherwise. 
DomainRegLen: 
Checks the domain registration duration via WHOIS. 
Legitimate (1) for registrations >= 1 year. 
Phishing (-1) for shorter durations. 
RequestURL: 
Examines external content (images, media) hosted outside the domain. 
Legitimate (1) if <22%, Suspicious (0) if 22-61%, Phishing (-1) if >61%. 
AnchorURL: 
Checks if anchor tags (<a>) contain unsafe links (e.g., #, javascript, mailto). 
Legitimate (1) if <31%, Suspicious (0) for 31-67%, Phishing (-1) for >67%. 
3. Feature Weighting and Scoring 
Each feature has a predefined weight based on its importance. 
The overall score is calculated by multiplying each feature's value by its weight 
and summing them up. 
4. Classification 
If the final score is negative, the URL is classified as Phishing. 
Otherwise, it is classified as Not Phishing. 
