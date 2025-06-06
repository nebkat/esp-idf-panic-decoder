# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
from itertools import groupby
from typing import List, Optional, Union, Dict, Tuple
import re
import subprocess

from .pc_address_matcher import PcAddressMatcher
from .output_helpers import red_print

# regex matches an potential address
ADDRESS_RE = re.compile(r'0x[0-9a-f]{8}', re.IGNORECASE)


class PcAddressDecoder:
    """
    Class for decoding possible addresses
    """

    def __init__(
            self, toolchain_prefix: str, elf_file: Union[List[str], str], rom_elf_file: Optional[str] = None
        ) -> None:
        self.toolchain_prefix = toolchain_prefix
        self.elf_files = elf_file if isinstance(elf_file, list) else [elf_file]
        self.rom_elf_file = rom_elf_file
        self.pc_address_matcher = [PcAddressMatcher(file) for file in self.elf_files]
        if self.rom_elf_file:
            self.pc_address_matcher.append(PcAddressMatcher(self.rom_elf_file))


    def decode_addresses(self, line: bytes) -> List[Tuple[str, List[dict]]]:
        """Decode possible addresses in a line, batching addr2line calls per ELF."""

        # Find all hex addresses
        addresses = re.findall(ADDRESS_RE, line.decode(errors='ignore'))

        # Mapped addresses
        mapped: Dict[str, List[dict]] = {}

        # Addresses left to find
        remaining = addresses.copy()

        # Check each elf file for matches
        for matcher in self.pc_address_matcher:
            elf_path = matcher.elf_path
            elf_addresses = [addr for addr in addresses if matcher.is_executable_address(int(addr, 16))]
            if not elf_addresses:
                continue

            # Lookup addresses using addr2line
            mapped_addresses = self.lookup_pc_address(elf_addresses, is_rom=(elf_path == self.rom_elf_file), elf_file=elf_path)

            # Store mapped addresses
            mapped.update(mapped_addresses)

            # Stop searching for addresses that have been found
            remaining = [addr for addr in remaining if addr not in mapped_addresses.keys()]

        # Return all mapped addresses that were found, in the original order
        return [(addr, mapped[addr]) for addr in addresses if addr in mapped]


    def lookup_pc_address(
        self,
        pc_addr: List[str],
        is_rom: bool = False,
        elf_file: str = ''
    ) -> Dict[str, List[dict]]:
        """
        Decode a list of addresses using addr2line, returning a map from each address string
        to a tuple (function_name, path:line).
        """
        elf_file = elf_file if elf_file else (self.rom_elf_file if is_rom else self.elf_files[0])  # type: ignore
        cmd = [f'{self.toolchain_prefix}addr2line', '-fiaC', '-e', elf_file, *pc_addr]

        try:
            batch_output = subprocess.check_output(cmd, cwd='.')
        except OSError as err:
            red_print(f'{" ".join(cmd)}: {err}')
            return {}
        except subprocess.CalledProcessError as err:
            red_print(f'{" ".join(cmd)}: {err}')
            red_print('ELF file is missing or has changed, the build folder was probably modified.')
            return {}

        decoded_output = batch_output.decode(errors='ignore')

        # Step 1: Split into sections where each section starts with an 8-hex-digit address
        sections = re.split(r'(?=0x[0-9A-Fa-f]{8}\r?\n)', decoded_output)

        result: Dict[str, List[dict]] = {}
        for section in sections:
            section = section.strip()
            if not section:
                continue

            # Step 2: Split the section by newlines
            lines = section.split('\n')

            # Step 3: First line is the address
            address = lines[0].strip()

            # Step 4: Build trace by consuming lines in pairs (function, path:line)
            trace: List[dict] = []
            for i in range(1, len(lines) - 1, 2):
                fn = lines[i].strip()
                path_line = lines[i + 1].strip()

                # Remove any " (discriminator N)" suffix
                path_line = re.sub(r' \(discriminator \d+\)$', '', path_line)

                # Split on the last colon before digits to separate path and line number
                parts = re.split(r':(?=\d+|\?$)', path_line, maxsplit=1)
                if len(parts) == 2:
                    path, line_str = parts
                    line_num = int(line_str) if line_str != '?' else '?'
                else:
                    path = parts[0]
                    line_num = 0

                if path == '??' and is_rom:
                    path = 'ROM'

                trace.append({'fn': fn, 'path': path, 'line': line_num})

            result[address] = trace

        return result
