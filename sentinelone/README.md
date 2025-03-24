# OpenBAS SentinelOne Endpoint Security Collector

The SentinelOne Endpoint Security collector.

**Note**: Requires subscription to the SentinelOne platform.

## Installation

Get a local copy
```commandline
git checkout https://github.com/OpenBAS-Platform/collectors
```

Install the SentinelOne Endpoint Security collector dependencies
```commandline
cd collectors/sentinelone
pip install -r requirements.txt
```

## Usage
```commandline
cd collectors/sentinelone
python -m sentinelone.openbas_sentinelone
```

## Configuration

The collector can be configured with the following variables:

| Config Parameter              | Docker env var              | Default                       | Description                                                                                  |
|-------------------------------|-----------------------------|-------------------------------|----------------------------------------------------------------------------------------------|
| `openbas`.`url`               | `OPENBAS_URL`               |                               | The URL to the OpenBAS instance                                                              |
| `openbas`.`token`             | `OPENBAS_TOKEN`             |                               | The auth token to the OpenBAS instance                                                       |
| `collector`.`id`              | `COLLECTOR_ID`              |                               | Unique ID of the running collector instance                                                  |
| `collector`.`name`            | `COLLECTOR_NAME`            |                               | Name of the collector (visible in UI)                                                        |
| `collector`.`type`            | `COLLECTOR_TYPE`            |                               | Type of the collector                                                                        |
| `collector`.`period`          | `COLLECTOR_PERIOD`          | 60                            | Period for collection cycle (int, seconds)                                                   |
| `collector`.`log_level`       | `COLLECTOR_LOG_LEVEL`       |                               | Threshold for log severity in console output                                                 |
| `collector`.`platform`        | `COLLECTOR_PLATFORM`        | `EDR`                         | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| `sentinelone`.`base_url`      | `SENTINELONE_BASE_URL`      | `b`                           | The base URL for the SentinelOne APIs.                                                       |
| `sentinelone`.`client_id`     | `SENTINELONE_CLIENT_ID`     | `CHANGEME`                    | The SentinelOne API client ID.                                                               |
| `sentinelone`.`client_secret` | `SENTINELONE_CLIENT_SECRET` | `CHANGEME`                    | The SentinelOne API client secret.                                                           |

**Note**: the SentinelOne credentials must have been granted the following privilege for this to work: `Alerts: Read and Write`

## Development

### Run the tests
In a terminal:
```commandline
cd collectors/sentinelone
python -m unittest
```

### JetBrains PyCharm configuration
To run the collector from within PyCharm, you must:

1. Ensure the requirements are installed correctly:
```commandline
pip install -r requirements.txt
```

2. Create a run configuration in PyCharm with the following settings:
* **Run**: module `sentinelone.openbas_sentinelone`
* **Working directory**: `...[path]\collectors\sentinelone`
* **Deactivate options**: `Add source roots to PYTHONPATH` and `Add content roots to PYTHONPATH`

You may now run or debug the module, run tests...
