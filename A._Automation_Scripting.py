import requests
import bs4
import re
import whois
import pandas as pd

# Install cyobstract from https://github.com/cmu-sei/cyobstract
from cyobstract import extract

# 1. Provide a script to automate the extraction of IP addresses, URLs and hashes from the following cyber threat report.
# “Opsec Mistakes Reveal COBALT MIRAGE Threat Actors”
# (https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors)
# You can use any open source tools and library to help with the extraction.

response = requests.get('https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors')
document = bs4.BeautifulSoup(response.content, 'html.parser')

results = extract.extract_observables(document.get_text(separator=' ', strip=True))

document_td = ''

for tag in document.find_all("td"):
    document_td = document_td + ' ' + tag.get_text(separator=' ', strip=True).replace(' ', '')
    
results_td = extract.extract_observables(document_td)

print('IPv4: \n', set(list(results['ipv4addr']) + list(results_td['ipv4addr'])))
print('\nIPv6: \n', set(list(results['ipv6addr']) + list(results_td['ipv6addr'])))
print('\nFQDN: \n', set(list(results['fqdn']) + list(results_td['fqdn'])))
print('\nURL: \n', set(list(results['url']) + list(results_td['url'])))
print('\nMD5: \n', set(list(results['md5']) + list(results_td['md5'])))
print('\nSHA1: \n', set(list(results['sha1']) + list(results_td['sha1'])))
print('\nSHA256: \n', set(list(results['sha256']) + list(results_td['sha256'])))
print('\n')

# 2. With the domains extracted, develop a python script to extract WHOIS information for each domain. 
# The output should be in a CSV file. You can use any open source library to develop the python script.

first_row_flag = True
ioc_domain_dict = {'ioc': [], 'domain_extracted': []}

for ioc in ['ipv4addr', 'ipv6addr', 'fqdn', 'url']:
    for domain in list(results[ioc]):
        w_dict = dict(whois.whois(domain))

        ioc_domain_dict['ioc'].append(ioc)
        ioc_domain_dict['domain_extracted'].append(domain)

        w_df = pd.DataFrame([w_dict])

        if first_row_flag == True:
            df = w_df
            first_row_flag = False
        else:
            df = pd.concat([df, w_df], axis=0, ignore_index=True).reset_index(drop = True)


ioc_domain_df = pd.DataFrame(ioc_domain_dict)
final_df = pd.concat([ioc_domain_df, df], axis=1)

# Sanity Checkpoint
print(final_df)

# Save pandas dataframe to .csv
final_df.to_csv('./A._Automation_Scripting_whois.csv')
