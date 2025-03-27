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

        if line.startswith('@@||') and line.endswith('^'):
            parsed_list.add(line)
        else:
            parts = line.split()
            if parts:
                domain = parts[-1]
                if is_valid_domain_name(domain):
                    parsed_list.add(f'@@||{domain}^')

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
    url_list = [
            'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt',
'https://raw.githubusercontent.com/zoonderkins/blahdns/refs/heads/master/hosts/whitelist.txt',
'https://raw.githubusercontent.com/ookangzheng/blahdns/master/hosts/whitelist.txt',
'https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/whitelist.txt',
'https://raw.githubusercontent.com/im-sm/Pi-hole-Torrent-Blocklist/main/all-torrent-trackres.txt',

'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/issues.txt',

'https://local.oisd.nl/extract/commonly_whitelisted.php',

'https://raw.githubusercontent.com/boutetnico/url-shorteners/master/list.txt',

'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt',

'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt',

'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt',

'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt',

'https://raw.githubusercontent.com/TogoFire-Home/AD-Settings/main/Filters/whitelist.txt',

'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/firefox.txt',

'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt',

'https://raw.githubusercontent.com/DandelionSprout/AdGuard-Home-Whitelist/master/whitelist.txt',

'https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt',

'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt',

'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/sensitive.txt',

'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt',

'https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt',

'https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/official-domains.txt',

'https://raw.githubusercontent.com/freekers/whitelist/master/domains/whitelist.txt',

'https://raw.githubusercontent.com/notracking/hosts-blocklists-scripts/master/hostnames.whitelist.txt',

'https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt']
    parsed_list = generate_parsed(url_list)
    write_to_file(parsed_list, 'allow_list.txt')
