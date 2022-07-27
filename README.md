# Use this

Tshark can be used to produce filtered pcap files which are smaller and could only contain packets relevant to a specific test case.

Only save packets containing "Security Mode Complete" messages:

```
tshark -2 -r open5gs_attach.pcap -w open5gs_attach_filtered.pcap -R "nas_5gs.mm.message_type == 0x5e"
```

Only save packets that contain the ngap protocol (here we pass an option to tshark to decode some extra layers if available):

```
tshark -2 -r open5gs_attach.pcap -w open5gs_attach_filtered.pcap -R "ngap" -o "nas-5gs.null_decipher":"TRUE"
```


# filter_pcap - DEPRECATED

Filters pcap or pcapng files in order to make them smaller and easier to read.
You can cut out/remove packets of specific protocols or you can keep only packets of specific protocols.

## Requirements

- Python3
- Scapy
  - ```pip3 install scapy```
  
  or 
  
  - ```pip3 install -r requirements.txt```

## Usage
usage: ```filter_pcap.py [-h] (-r PROTOCOL [PROTOCOL ...] | -k PROTOCOL [PROTOCOL ...]) <input_file>```

Filters pcap or pcapng files. You can specify if packets of specific protocols (see scapy.ls() for supported protocols) should be kept or removed. The output file will be placed besides the input file (e.g. test.pcap -> test_filtered.pcap)

positional arguments:

```<input_file>``` the input file that will be filtered

optional arguments:

```-h, --help```            show this help message and exit

```-r PROTOCOL [PROTOCOL ...], --remove PROTOCOL [PROTOCOL ...]```
                        a list of protocols that should be removed
                        
```-k PROTOCOL [PROTOCOL ...], --keep PROTOCOL [PROTOCOL ...]```
                        a list of protocols that should be kept

examples:

  ```./filter_pcap.py test.pcap -r TCP UDP``` (removes TCP and UDP packets)
  
  ```./filter_pcap.py test.pcap -k TCP``` (keeps only TCP packets)
