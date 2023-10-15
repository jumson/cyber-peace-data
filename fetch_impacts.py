import requests
import json
from datetime import datetime

# Define the URL and headers
url = 'https://cyberconflicts.cyberpeaceinstitute.org/api/impacts'
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'https://cyberconflicts.cyberpeaceinstitute.org/threats/attack-details',
    'Content-Type': 'application/json',
    'Connection': 'keep-alive',
    'Cookie': '_ga_83HJ51ZJF1=GS1.1.1692621604.1.1.1692621627.37.0.0; _ga=GA1.2.2137845171.1692621604; _gcl_au=1.1.1767381862.1692621604; _ga_VZ72HDZLDW=GS1.1.1696982856.3.1.1696982918.0.0.0; _gid=GA1.2.776793772.1696982857',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'TE': 'trailers'
}

# Make the request
response = requests.get(url, headers=headers)

# Check if the request was successful
if response.status_code == 200:
    # Parse the JSON data
    parsed_data = json.loads(response.text)
    
    # Generate a filename with the current date
    current_date = datetime.now().strftime('%Y-%m-%d')
    filename = f"data_{current_date}.json"
    
    # Save the JSON data to a file
    with open(filename, 'w') as f:
        json.dump(parsed_data, f, indent=4)
    
    print(f"Data fetched and saved successfully to {filename}!")
else:
    print(f"Failed to fetch data. Status code: {response.status_code}")
