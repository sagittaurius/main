import re
import requests

def is_valid_domain_name(domain: str) -> bool:
    domain_regex = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    )
    return bool(domain_regex.match(domain))

def generate():
    url_list = ['https://raw.githubusercontent.com/sagittaurius/main/main/whitelist']
    parsed_list = [requests.get(url).text for url in url_list]

    def parse_filter_content(content):
        parsed_list = set()
        for line in content.split('\n'):
            line = line.strip()

            if line.startswith('||') and line.endswith('^'):
                parsed_list.add(line)
            else:
                parts = line.split()
                domain = parts[-1]
                if is_valid_domain_name(domain):
                    parsed_list.add(f'||{domain}^')

        return parsed_list

    with open('adblock_allowed.txt', 'w') as f:
        f.write(parsed_list)
