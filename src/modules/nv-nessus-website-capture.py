import requests
import argparse
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(description="Script to process URL and page arguments.")
parser.add_argument("-p", "--pages", type=int, required=True, help="The page parameter to process")
args = parser.parse_args()

l = []

for page in range(1, args.pages+1):
    url = f'https://www.tenable.com/plugins/search?q=Jenkins&sort=&page={page}'
    response = requests.get(url)
    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Find all <tr> elements
        rows = soup.find_all("tr")
        
        # Loop through each row
        for row in rows:
            # Get the first <td> and find <a> inside it
            first_td = row.find("td") # type: ignore
            if first_td:
                link = first_td.find("a") # type: ignore
                if link:
                    l.append(int(link.text.strip())) # type: ignore
            
            # Get the second <td> value
            tds = row.find_all("td") # type: ignore
            if len(tds) > 1:
                second_td = tds[1]
                print(f"  # {link.text.strip()} - {second_td.text.strip()}") # type: ignore
    else:
        pass

print(l)