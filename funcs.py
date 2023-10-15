# 11 October 2023

import json
import sqlite3
import csv
from datetime import datetime
from typing import List, Dict, Union, Tuple, Optional, Any, Set
import requests

# Initial Variables
DATABASE_NAME = 'events2.db'
DATAFILE_NAME = 'data_2023-10-11.json'

def create_database() -> None:
    """
    Create a SQLite database with tables named 'events', 'threat_actors', and 'sources'.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Create events table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        _key TEXT PRIMARY KEY,
        description TEXT,
        eventConfidence TEXT,
        eventDateFrom TEXT,
        eventName TEXT,
        eventType TEXT,
        country TEXT,
        countryAbbreviation TEXT,
        threatActorKey TEXT,
        FOREIGN KEY (threatActorKey) REFERENCES threat_actors(_key)
    );
    ''')
    
    # Create threat_actors table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threat_actors (
        _key TEXT PRIMARY KEY,
        name TEXT,
        type TEXT,
        profiled TEXT,
        identifiers TEXT,
        active TEXT,
        apt TEXT,
        allegiance TEXT,
        origin TEXT,
        targetedSectors TEXT,
        description TEXT
    );
    ''')
    
    # Create sources table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        eventKey TEXT,
        URL TEXT,
        title TEXT,
        sourceName TEXT,
        FOREIGN KEY (eventKey) REFERENCES events(_key)
    );
    ''')
    
    conn.commit()
    conn.close()


def insert_data(data: List[Dict[str, Any]]) -> None:
    """
    Insert the data into SQLite database tables: events, threat_actors, and sources.

    Parameters:
        data (List[Dict[str, Any]]): A list of dictionaries, each representing an event.

    Returns:
        None
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    for record in data:
        event = record.get('event') or {}
        threat_actor = record.get('threatActor') or {}
        location = record.get('location') or {}
        sources = record.get('sources') or []

        # Insert into events table
        if event.get('_key'):
            cursor.execute("SELECT 1 FROM events WHERE _key=?", (event['_key'],))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO events (_key, description, eventConfidence, eventDateFrom, eventName, eventType, country, countryAbbreviation, threatActorKey) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (event.get('_key'), event.get('description'), event.get('eventConfidence'), event.get('eventDateFrom'), event.get('eventName'), event.get('type'),
                     location.get('country'), location.get('countryAbbreviation'), threat_actor.get('_key')))

        # Insert into threat_actors table
        if threat_actor.get('_key'):
            cursor.execute("SELECT 1 FROM threat_actors WHERE _key=?", (threat_actor['_key'],))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO threat_actors (_key, name, type, profiled, identifiers, active, apt, allegiance, origin, targetedSectors, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (threat_actor.get('_key'), threat_actor.get('name'), threat_actor.get('type'), threat_actor.get('profiled'), threat_actor.get('identifiers'),
                     threat_actor.get('active'), threat_actor.get('apt'), threat_actor.get('allegiance'), threat_actor.get('origin'), threat_actor.get('targetedSectors'), threat_actor.get('Description')))

        # Insert into sources table
        for source in sources:
            cursor.execute("SELECT 1 FROM sources WHERE URL=?", (source.get('URL'),))
            if cursor.fetchone() is None:
                cursor.execute("INSERT INTO sources (eventKey, URL, title, sourceName) VALUES (?, ?, ?, ?)",
                               (event.get('_key'), source.get('URL'), source.get('title'), source.get('sourceName')))

    conn.commit()
    conn.close()
    

class FetchDataError(Exception):
    """Exception raised when data fetching fails."""
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.message = f"Failed to fetch data. Status code: {self.status_code}"
        super().__init__(self.message)

def get_cpi_data() -> Union[str, None]:
    """
    Fetch data from the Cyber Conflicts API and save it to a JSON file.
    
    Returns:
        str: Filename where the data is saved if the operation is successful.
        None: Returns None if an error occurs.
        
    Raises:
        FetchDataError: An exception is raised if fetching the data fails.
    """
    
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

    try:
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
            return filename
        else:
            raise FetchDataError(response.status_code)
    except FetchDataError as e:
        print(e)
        return None

def search_threat_actor(threat_actor_key: str) -> None:
    """
    Search for a threat actor in the 'threat_actors' table and print their profile.
    """
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Query the 'threat_actors' table
    cursor.execute("SELECT * FROM threat_actors WHERE _key = ?", (threat_actor_key,))
    result = cursor.fetchone()
    
    if result:
        print("Threat Actor Profile:")
        print(f"Key: {result[0]}")
        print(f"Name: {result[1]}")
        print(f"Type: {result[2]}")
        print(f"Profiled: {result[3]}")
        print(f"Identifiers: {result[4]}")
        print(f"Active: {result[5]}")
        print(f"APT: {result[6]}")
        print(f"Allegiance: {result[7]}")
        print(f"Origin: {result[8]}")
        print(f"Targeted Sectors: {result[9]}")
        print(f"Description: {result[10]}")
    else:
        print("Threat actor not found.")
    
    # Close the connection
    conn.close()

    # Example usage
    # search_threat_actor("ITARMYOFUKRAINE")

def search_events_by_date_range(start_date: str, end_date: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events within a specific date range. If existing_results is provided, filters those results instead of querying the database.
    
    Args:
        start_date (str): The start date in the format 'YYYY-MM-DD'.
        end_date (str): The end date in the format 'YYYY-MM-DD'.
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data within the specified date range.
    """
    # Convert the input dates to the same format as in the database (ISO 8601)
    start_date_iso = datetime.strptime(start_date, '%Y-%m-%d').isoformat() + 'T00:00:00Z'
    end_date_iso = datetime.strptime(end_date, '%Y-%m-%d').isoformat() + 'T00:00:00Z'
    
    if existing_results is None:
        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # Execute the query to find events within the date range
        cursor.execute('''
        SELECT * FROM events
        WHERE eventDateFrom >= ? AND eventDateFrom <= ?;
        ''', (start_date_iso, end_date_iso))
        
        # Fetch all matching records
        results = cursor.fetchall()
        
        # Close the database connection
        conn.close()
    else:
        results = [event for event in existing_results if start_date_iso <= event[3] <= end_date_iso]
    
    return results
 
 
def search_ukraine_attacked_by_russia(existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events where Ukraine is attacked by Russia.
        
    Args:
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data where Ukraine is attacked by Russia.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events INNER JOIN threat_actors ON events.threatActorKey = threat_actors._key WHERE country=? AND allegiance=?", ('Ukraine', 'Russian Federation'))
        results = cursor.fetchall()
        conn.close()
    else:
        results = [event for event in existing_results if event[-4] == 'Russian Federation']
    return results

def write_to_csv(results: List[Tuple], filename: str) -> None:
    """
    Write the query results to a CSV file.
    
    Args:
        results (List[Tuple]): List of tuples containing event data.
        filename (str): The name of the CSV file to write to.
        
    Returns:
        None
    """
    headers = [
        "_key", "description", "eventConfidence", "eventDateFrom", "eventName", "eventType",
        "country", "countryAbbreviation", "threatActorKey", "name", "type", "profiled",
        "identifiers", "active", "apt", "allegiance", "origin", "targetedSectors", "description"
    ]
    with open(filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(headers)
        for row in results:
            csvwriter.writerow(row)

def search_cyber_attacks_by_date_range_and_allegiance(start_date: str, end_date: str, allegiance: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for cyber attacks within a specific date range and by a specific threat actor allegiance.
    If existing_results is provided, filters those results instead of querying the database.
    
    Args:
        start_date (str): The start date in the format 'YYYY-MM-DD'.
        end_date (str): The end date in the format 'YYYY-MM-DD'.
        allegiance (str): The allegiance of the threat actor.
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data related to cyber attacks by the specified allegiance.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events INNER JOIN threat_actors ON events.threatActorKey = threat_actors._key WHERE eventDateFrom BETWEEN ? AND ?", (start_date, end_date))
        all_events = cursor.fetchall()
        conn.close()
    else:
        all_events = existing_results
    
    filtered_events = [event for event in all_events if event[-4] == allegiance]
    
    return filtered_events
    

def search_by_threat_actor_key(threat_actor_key: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events by a specific threat actor key.
    
    Args:
        threat_actor_key (str): The key of the threat actor.
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data related to the specified threat actor key.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE threatActorKey=?", (threat_actor_key,))
        results = cursor.fetchall()
        conn.close()
    else:
        results = [event for event in existing_results if event[8] == threat_actor_key]
    return results

def search_by_threat_actor_name(threat_actor_name: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events by a specific threat actor name.
    
    Args:
        threat_actor_name (str): The name of the threat actor.
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data related to the specified threat actor name.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events INNER JOIN threat_actors ON events.threatActorKey = threat_actors._key WHERE name=?", (threat_actor_name,))
        results = cursor.fetchall()
        conn.close()
    else:
        results = [event for event in existing_results if event[-10] == threat_actor_name]
    return results

def search_by_threat_actor_affiliation(affiliation: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events by a specific threat actor affiliation.
    
    Args:
        affiliation (str): The affiliation of the threat actor.
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data related to the specified threat actor affiliation.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events INNER JOIN threat_actors ON events.threatActorKey = threat_actors._key WHERE allegiance=?", (affiliation,))
        results = cursor.fetchall()
        conn.close()
    else:
        results = [event for event in existing_results if event[-4] == affiliation]
    return results

def search_by_event_type(event_type: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events by a specific event type.
    
    Args:
        event_type (str): The type of the event to search for (e.g., 'Malware', 'Phishing').
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data related to the specified event type.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE eventType=?", (event_type,))
        results = cursor.fetchall()
        conn.close()
    else:
        results = [event for event in existing_results if event[4] == event_type]
        
    return results

# how do  I search for keywords inside event description and event name?
def search_by_keyword_in_description_and_name(keyword: str, existing_results: Optional[List[Tuple]] = None) -> List[Tuple]:
    """
    Search for events by a keyword present in the event description and/or name.
    
    Args:
        keyword (str): The keyword to search for in event descriptions and names.
        existing_results (Optional[List[Tuple]]): Existing results to filter, if available.
        
    Returns:
        List[Tuple]: List of tuples containing event data that includes the keyword in their descriptions and/or names.
    """
    if existing_results is None:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # Using the LIKE operator to search for the keyword in the event description and event name
        query = """SELECT * FROM events 
                   WHERE description LIKE ? 
                   OR eventName LIKE ?"""
                   
        cursor.execute(query, (f"%{keyword}%", f"%{keyword}%"))
        results = cursor.fetchall()
        conn.close()
    else:
        results = [record for record in existing_results if keyword.lower() in record[1].lower() or keyword.lower() in record[4].lower()]

    return results
    

# using these functions, how do I create a list of all event types, all threat actor names and threat actor keys?
def get_unique_event_types() -> Set[str]:
    """
    Query the database to get all unique event types.
    
    Returns:
        Set[str]: A set containing all unique event types.
    """
    events = search_by_event_type('%')  # Using SQL's wildcard to fetch all types
    unique_types = {event[4] for event in events}  # eventType is at index 4
    return unique_types

def get_unique_threat_actor_names() -> Set[str]:
    """
    Query the database to get all unique threat actor names.
    
    Returns:
        Set[str]: A set containing all unique threat actor names.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT name FROM threat_actors")
    results = cursor.fetchall()
    conn.close()
    unique_names = {result[0] for result in results}
    return unique_names

def get_unique_threat_actor_keys() -> Set[str]:
    """
    Query the database to get all unique threat actor keys.
    
    Returns:
        Set[str]: A set containing all unique threat actor keys.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT _key FROM threat_actors")
    results = cursor.fetchall()
    conn.close()
    unique_keys = {result[0] for result in results}
    return unique_keys
    
def get_unique_event_types_with_count() -> Dict[str, int]:
    """
    Query the database to get all unique event types and their counts.
    
    Returns:
        Dict[str, int]: A dictionary mapping each unique event type to its count.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT eventType, COUNT(*) FROM events GROUP BY eventType")
    results = cursor.fetchall()
    conn.close()
    
    return {result[0]: result[1] for result in results}

def get_unique_threat_actor_names_with_count() -> Dict[str, int]:
    """
    Query the database to get all unique threat actor names and their counts.
    
    Returns:
        Dict[str, int]: A dictionary mapping each unique threat actor name to its count.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT name, COUNT(*) FROM threat_actors GROUP BY name")
    results = cursor.fetchall()
    conn.close()
    
    return {result[0]: result[1] for result in results}

def get_unique_threat_actor_keys_with_count() -> Dict[str, int]:
    """
    Query the database to get all unique threat actor keys and their counts.
    
    Returns:
        Dict[str, int]: A dictionary mapping each unique threat actor key to its count.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT _key, COUNT(*) FROM threat_actors GROUP BY _key")
    results = cursor.fetchall()
    conn.close()
    
    return {result[0]: result[1] for result in results}

   
