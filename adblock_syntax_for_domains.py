import re
import requests

def is_valid_domain_name(domain: str) -> bool:
    domain_regex = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    )
    return bool(domain_regex.match(domain))

def parse_filter_content(content: str) -> set:
    parsed_list = set()
    lines = content.split('\n')
    for line in lines:
        line = line.strip()

        if line.startswith('||') and line.endswith('^'):
            parsed_list.add(line)
        else:
            parts = line.split()
            if parts:
                domain = parts[-1]
                if is_valid_domain_name(domain):
                    parsed_list.add(f'||{domain}^')

    return parsed_list


def generate_parsed(url_list: list) -> set:
    parsed_list = set()
    for url in url_list:
        response = requests.get(url)
        if response.status_code == 200:
            content = response.text
            parsed_list.update(parse_filter_content(content))

    return parsed_list

def write_to_file(parsed_list: set, filename: str) -> None:
    with open(filename, 'w') as f:
        for item in parsed_list:
            f.write(item + '\n')

if __name__ == "__main__":
    url_list = ['https://raw.githubusercontent.com/sagittaurius/main/main/whitelist']
    parsed_list = generate_parsed(url_list)
    write_to_file(parsed_list, 'adblock_allowed.txt')
