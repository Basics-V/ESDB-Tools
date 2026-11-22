#@author PlatinumMaster
#@category GUI
#@language Python

from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException

import importlib.util
import subprocess
import sys
if importlib.util.find_spec("yaml") is None:
    print("Installing pyyaml...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])
import yaml

def get_file_from_user():
    return askFile("Select input ESDB (.yml)", "Choose")

file_path = get_file_from_user()
if file_path:
    # Load the ESDB.
    with open(file_path.getAbsolutePath(), 'r') as f:
        esdb = yaml.load(f, Loader=yaml.SafeLoader)

    # Load the segment map, then build an segment -> symbol meta map.
    esdb_segment_map = {}
    for segment in esdb['Segments']:
        esdb_segment_map |= {
            segment['ID'] : {
                'Name' : segment['Name'],
                'Type' : segment['Type'],
            }
        }

    esdb_symbol_map = {}
    for symbol_meta in esdb['Symbols']:
        # If not already defined, define it.
        segment_meta = esdb_segment_map[symbol_meta['Segment']]
        if (segment_name := segment_meta['Name']) not in esdb_symbol_map:
            esdb_symbol_map.update({
                segment_name : {}
            })

        # Address -> symbol mapping (for reverse lookup).
        esdb_symbol_map[segment_name] |= {
            symbol_meta['Address'] : symbol_meta['Name'],
        }

    def get_symbol_by_address(address):
        if address in esdb_symbol_map.keys():
            return esdb_symbol_map[address]
        return None

    memory = currentProgram.getMemory()
    ghidra_segments = memory.getBlocks()
    ghidra_segment_map = {}
    for segment in ghidra_segments:
        ghidra_segment_map |= {
            segment.getName() : {
                'Start' : segment.getStart(),
                'End' : segment.getEnd(),
            }
        }

    symbol_table = currentProgram.getSymbolTable()
    for segment_name, symbols in esdb_symbol_map.items():
        ghidra_segment_name_candidates = []
        ghidra_segment_name = ''

        if segment_name.startswith('ARM9'):
            ghidra_segment_name_candidates.append('ARM9')
        elif segment_name.startswith('OVL'):
            tokens = segment_name.split('_')
            overlay_tag, overlay_number = tokens[:2]
            try:
                overlay_number = int(overlay_number)
                ghidra_segment_name_candidates.append(f'overlay_{overlay_number:03d}')
                ghidra_segment_name_candidates.append(f'overlay_d_{overlay_number:03d}')
            except:
                pass

        for name in ghidra_segment_name_candidates:
            if name in ghidra_segment_map:
                ghidra_segment_name = name
                print(f'Found segment {ghidra_segment_name}!')
                break
        
        if ghidra_segment_name == '':
            print(f'Skipping segment {segment_name}')
            continue

        segment_meta = ghidra_segment_map[ghidra_segment_name] 
        
        print(f'Renaming symbols in {ghidra_segment_name}...')

        for address, label in symbols.items():
            corrected_address = address - (address & 1)
            ghidra_symbols = list(symbol_table.getSymbols(toAddr(corrected_address)))
            ghidra_symbols.extend(list(symbol_table.getSymbols(toAddr(f"{ghidra_segment_name}::{hex(corrected_address)}"))))
            ghidra_symbols.extend(list(symbol_table.getSymbols(toAddr(f"{ghidra_segment_name}::{hex(address)}"))))
            if ghidra_symbols:
                for ghidra_symbol in ghidra_symbols:
                    addr = ghidra_symbol.getAddress()
                    if addr and addr.isMemoryAddress():
                        block = currentProgram.getMemory().getBlock(addr)
                        if block and block.getName() == ghidra_segment_name:
                            old_name = ghidra_symbol.getName()
                            try:
                                new_label = label
                                ghidra_symbol_address = addr.getOffset()
                                print(f"Ghidra sym addr: {hex(ghidra_symbol_address)}")
                                if (ghidra_symbol_address) != corrected_address:
                                    delta = corrected_address - ghidra_symbol_address
                                    new_label = f'_{new_label}_{hex(delta)}'
                                ghidra_symbol.setName(new_label, SourceType.USER_DEFINED)
                                print(f"Renamed {old_name} to {new_label}")
                                break
                            except:
                                pass

        