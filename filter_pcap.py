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

    def sorter(x): return (x.__name__.lower().index(name),
                           len(x.__name__))
    return sorted((layer for layer in conf.layers
                   if (isinstance(layer.__name__, str) and
                       pattern.search(layer.__name__)) or
                   (isinstance(layer.name, str) and
                    pattern.search(layer.name))),
                  key=sorter)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
                                     description="Filters pcap or pcapng files. You can specify if packages of specific protocols (see scapy.ls() for supported protocols) should be kept or removed. The output file will be placed besides the input file (e.g. test.pcap -> test_filtered.pcap)", epilog=f"examples:\n  ./filter_pcap.py test.pcap -r TCP UDP (removes TCP and UDP packages)\n  ./filter_pcap.py test.pcap -k TCP (keeps only TCP packages)")
    parser.add_argument("input_file", metavar="<input_file>",
                        type=str, help="the input file that will be filtered")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r", "--remove", nargs="+", default=[], metavar="PROTOCOL",
                       help="a list of protocols that should be removed")
    group.add_argument("-k", "--keep", nargs="+", default=[], metavar="PROTOCOL",
                       help="a list of protocols that should be kept")

    args = parser.parse_args()

    input_file = args.input_file
    output_file = input_file.replace(".pcap", "_filtered.pcap")

    protocols = []
    if len(args.remove) != 0:
        for protocol_string in args.remove:
            protocols.extend(get_protocols_by_name(protocol_string))
    else:
        for protocol_string in args.keep:
            protocols.extend(get_protocols_by_name(protocol_string))

    protocol_names = list(map(lambda prot: prot.__name__, protocols))

    pkts = rdpcap(input_file)

    if len(args.remove) != 0:
        print(
            f"Removing all packages containing {protocol_names}...")
        filtered = list(itertools.filterfalse(lambda pkt: any(
            pkt for prot in protocols if prot in pkt), pkts))
        print(f"Removed {len(pkts) - len(filtered)} of {len(pkts)} packages!")
    else:
        print(
            f"Keeping only packages containing {protocol_names}...")
        filtered = list(filter(lambda pkt: any(
            pkt for prot in protocols if prot in pkt), pkts))
        print(f"Kept {len(filtered)} of {len(pkts)} packages!")

    wrpcap(output_file, filtered)
