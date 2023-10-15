# Cyber Peace Data Interface

This Python project is a toolkit of utility scripts and Jupyter notebooks designed to ingest, query, and analyze a database of cyber-attacks based on data collected by the [Cyber Peace Institute](https://cyberconflicts.cyberpeaceinstitute.org/threats/attack-details). No installation is required; just download the scripts or notebooks you want to use.

## Table of Contents

- [Getting Started](#getting-started)
  - [Database Operations](#database-operations)
  - [Data Ingestion](#data-ingestion)
  - [Data Queries](#data-queries)
  - [Data Export](#data-export)
  - [Statistics and Analysis](#statistics-and-analysis)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

Download the repository and navigate to the project directory where you can directly execute the Python scripts or open the Jupyter notebooks. 

### Usage

#### Database Operations

##### `create_database() -> None`

Create an SQLite database with tables named 'events', 'threat_actors', and 'sources'.

#### Example
```python
from your_module import create_database

# Initialize the database
create_database()
```

#### Data Ingestion

##### `insert_data(data: List[Dict[str, Any]]) -> None`

Insert a batch of cyber-attack data into the SQLite database.

##### `get_cpi_data() -> Union[str, None]`

Fetch data from the Cyber Conflicts API and save it to a JSON file.

#### Data Ingestion Example Example
```python
from funcs import *
DATABASE_NAME = 'events2.db'

filename = get_cpi_data()
# Initialize the database
create_database()

# Example of loading data from a file
with open(filename, 'r') as f:
    data = json.load(f)

# Insert the data into the database
insert_data(data)
```

#### Data Queries

Here are some notable query functions, designed to help you query specific information easily.

- `search_threat_actor(threat_actor_key: str) -> None`
- `search_events_by_date_range(start_date: str, end_date: str) -> List[Tuple]`
- `search_ukraine_attacked_by_russia() -> List[Tuple]`
- `search_cyber_attacks_by_date_range_and_allegiance(start_date: str, end_date: str, allegiance: str) -> List[Tuple]`
- `search_by_threat_actor_key(threat_actor_key: str) -> List[Tuple]`

##### `write_to_csv(results: List[Tuple], filename: str) -> None`

Write the query results to a CSV file.

#### Example data query (after creating database)
```python
from funcs import *
DATABASE_NAME = 'events2.db'

results = search_events_by_date_range('2022-01-01', '2022-02-01')

write_to_csv(results, 'events_january.csv')
```

#### Statistics and Analysis

- `get_unique_event_types() -> Set[str]`
- `get_unique_threat_actor_names() -> Set[str]`
- `get_unique_event_types_with_count() -> Dict[str, int]`


## Contributing

Interested in contributing? Please read through our [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This toolkit is licensed under the MIT License. For more details, see [LICENSE.md](LICENSE.md).

---

Feel free to adapt this `README.md` according to your project's specific needs. The code examples are placeholders; please replace them with the actual functions from your modules.