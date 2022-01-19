#!/usr/bin/python3

import argparse
from argparse import RawTextHelpFormatter
import re
from scapy.all import *


def get_protocols_by_name(name) -> []:
    pattern = re.compile(
        name,
        re.I
    )

    name = name.lower()

    layers = [layer for layer in conf.layers
              if (isinstance(layer.__name__, str) and
                  pattern.search(layer.__name__)) or
              (isinstance(layer._name, str) and
               pattern.search(layer._name))]

    return sorted(layers, key=lambda x: x.__name__)


def remove_or_keep(args):
    protocol_strings = args.remove + args.keep
    protocols = []

    for protocol_string in protocol_strings:
        protocols.extend(get_protocols_by_name(protocol_string))

    if len(protocols) == 0:
        print(f"The following protocol(s) could not be found "
              f"in default scapy:{protocol_strings}")

        for prot in protocol_strings:
            print(f"Trying load_contrib(\"{prot}\")")
            try:
                load_contrib(f"{prot}")
            except ModuleNotFoundError as err:
                print(f"{err.message}")

    for protocol_string in protocol_strings:
        protocols.extend(get_protocols_by_name(protocol_string))

    if len(protocols) == 0:
        print(f"Could not find protocol(s) in \'contrib\' either. Exiting...")
        exit()

    protocol_names = list(map(lambda prot: prot.__name__, protocols))

    pkts = rdpcap(input_file)

    work_done = 0

    if len(args.remove) != 0:
        print(
            f"Removing all packets containing {protocol_names}...")
        filtered = list(itertools.filterfalse(lambda pkt: any(
            pkt for prot in protocols if prot in pkt), pkts))
        work_done = len(pkts) - len(filtered)
        print(f"Removed {len(pkts) - len(filtered)} of {len(pkts)} packets!")
    else:
        print(
            f"Keeping only packets containing {protocol_names}...")
        filtered = list(filter(lambda pkt: any(
            pkt for prot in protocols if prot in pkt), pkts))
        work_done = len(filtered)
        print(f"Kept {len(filtered)} of {len(pkts)} packets!")

    return (work_done, filtered)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
                                     description="Filters pcap or pcapng files"
                                     ". You can specify if packets of specific"
                                     " protocols (see scapy.ls() and"
                                     " scapy.contrib for supported"
                                     " protocols) should be kept or removed."
                                     " The output file will be stored next to"
                                     " the input file (e.g. test.pcap ->"
                                     " test_filtered.pcap)",
                                     epilog=f"examples:\n  ./filter_pcap.py"
                                     " test.pcap -r TCP UDP (removes TCP and"
                                     " UDP packets)\n  ./filter_pcap.py"
                                     " test.pcap -k TCP (keeps only TCP"
                                     " packets)\n  ./filter_pcap.py test.pcap"
                                     " -f \"ip src 127.0.0.1\" (keeps only"
                                     " packets matching the filter)")
    parser.add_argument("input_file", metavar="<input_file>",
                        type=str, help="the input file that will be filtered")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r", "--remove", nargs="+", default=[],
                       metavar="PROTOCOL",
                       help="a list of protocols that should be removed")
    group.add_argument("-k", "--keep", nargs="+", default=[],
                       metavar="PROTOCOL",
                       help="a list of protocols that should be kept")
    group.add_argument("-f", "--filter", type=str, metavar="FILTER",
                       help="a filter string (BPF only!), matching packets"
                       " will be kept(!)")

    args = parser.parse_args()

    input_file = args.input_file
    output_file = input_file.replace(".pcap", "_filtered.pcap")

    if len(args.remove) > 0 or len(args.keep):
        (work_done, filtered) = remove_or_keep(args)
    else:
        filtered = sniff(offline=input_file, filter=args.filter)
        work_done = abs(len(filtered) - len(sniff(offline=input_file)))

    if work_done == 0:
        print(f"Nothing to save. Exiting... ")
        exit()

    wrpcap(output_file, filtered)
