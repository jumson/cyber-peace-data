# Threat Intelligence Data Format Description

This document describes the data format for storing threat intelligence events. The data is structured in JSON format and encompasses detailed information about cybersecurity events, impacts, threat actors, and more. Below is a breakdown of the key fields within the data:

## Root Level Fields

- **event**: Information about a specific cybersecurity event.
- **impacts**: An array of impact descriptions associated with the event.
- **location**: Geographical information regarding where the event took place.
- **otherThreatActors**: An array of other threat actors involved in the event.
- **sectors**: An array of sectors targeted in the event.
- **sources**: An array of source references related to the event.
- **threatActor**: Information about the main threat actor involved in the event.

### `event` Object

- **_key**: Unique key identifier for the event.
- **description**: Description of the event in textual form.
- **eventConfidence**: Confidence level of the event (e.g., "Probable").
- **eventDateFrom**: Date and time from when the event originated, in ISO 8601 format.
- **eventName**: Name of the event or campaign.
- **type**: Type of threat (e.g., "Wiper").

### `impacts` Array

Each object in the array has:

- **category**: Category of the impact (e.g., "Destruction").
- **description**: Textual description of the impact.

### `location` Object

- **country**: Full name of the country where the event took place.
- **countryAbbreviation**: Abbreviation of the country name.

### `otherThreatActors` Array

Currently an empty array, reserved for future use.

### `sectors` Array

Each object in the array has:

- **division**: Name of the sector division targeted in the event (e.g., "ICT").

### `sources` Array

Each object in the array has:

- **URL**: URL of the source information.
- **title**: Title of the source information (if available).
- **sourceName**: Name of the source entity (e.g., "Microsoft").

### `threatActor` Object

- **_key**, **_id**, **_rev**: Unique identifiers for the threat actor.
- **name**: Name of the threat actor.
- **type**: Type of threat actor (e.g., "Nation State").
- **profiled**: Whether the actor is profiled ("Yes" or "No").
- **identifiers**: Aliases or other identifiers associated with the threat actor.
- **active**: Year when the actor was first noticed to be active.
- **apt**: Specifies if the actor is considered an Advanced Persistent Threat (APT).
- **allegiance**: Country allegiance of the threat actor.
- **origin**: Country of origin abbreviation.
- **targetedSectors**: Sectors targeted by the threat actor.
- **Description**: Description of the threat actor’s activities.

---

This data format provides a comprehensive view of threat intelligence events, ideal for analysis and cross-referencing with other data sets.