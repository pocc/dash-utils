# dash-utils

Methods that do things that the Meraki API cannot currently do. This file will
contain utilities that will work provided correct Meraki dashboard 
user/pass/(tfa).

## Methods
### Implemented Methods
* **check_for_tshark**: Verify that tshark can be accessed via shell.
* **filter_pcap**: Takes a pcap, filters it, and then outputs the result.

### Planned Methods
* **set_tcpdump_prefs**: Set the tcpdump settings in order to download a pcap.
* **get_tcpdump_pcap**: Download a pcap from a network
* **get_eventlogs**: Get the event logs for a network with filters