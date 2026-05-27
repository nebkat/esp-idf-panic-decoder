# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import atexit
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

from .output_helpers import red_print
from .pc_address_matcher import PcAddressMatcher

# regex matches an potential address
ADDRESS_RE = re.compile(r'0x[0-9a-f]{8}', re.IGNORECASE)

# regex to split address sections in addr2line output (lookahead to preserve address when splitting)
ADDR2LINE_ADDRESS_LOOKAHEAD_RE = re.compile(r'(?=0x[0-9a-f]{8}\r?\n)')
# regex matches filename and line number in addr2line output (and ignores discriminators)
ADDR2LINE_FILE_LINE_RE = re.compile(r'(?P<file>.*):(?P<line>\d+|\?)(?: \(discriminator \d+\))?$')

# Sentinel written after each request so we know where addr2line's response ends.
# 0xfefefefe is a classic uninit-memory marker, well outside any ESP code region,
# so it will not pass PcAddressMatcher.is_executable_address and cannot collide with
# a real lookup. The regex matches the full 3-line sentinel response atomically
# (echoed address + ?? + ??:0), tolerating leading zero padding when addr2line widens
# to the ELF pointer width (e.g. `0x00000000fefefefe` on a 64-bit target).
ADDR2LINE_SENTINEL_INPUT = '0xfefefefe'
ADDR2LINE_SENTINEL_RE = re.compile(r'0x0*fefefefe\r?\n\?\?\r?\n\?\?:0\r?\n')

# Decoded PC address trace
@dataclass
class PcAddressLocation:
    func: str
    path: str
    line: str

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

        # Persistent addr2line subprocesses, keyed by ELF path. addr2line is slow to
        # start (loads and indexes the ELF) but fast once running, so we keep one
        # alive per ELF and feed it addresses on stdin.
        self._processes: Dict[str, subprocess.Popen] = {}
        atexit.register(self._terminate_all)

    def close(self) -> None:
        """Terminate any cached addr2line subprocesses. Optional — atexit will handle it otherwise."""
        self._terminate_all()

    def _spawn(self, elf_file: str) -> Optional[subprocess.Popen]:
        cmd = [f'{self.toolchain_prefix}addr2line', '-fiaC', '-e', elf_file]
        try:
            return subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=True,
                cwd='.',
            )
        except OSError as err:
            red_print(f'{" ".join(cmd)}: {err}')
            return None

    def _get_process(self, elf_file: str) -> Optional[subprocess.Popen]:
        proc = self._processes.get(elf_file)
        if proc is not None and proc.poll() is None:
            return proc
        # Either no process yet or the previous one exited — (re)spawn.
        if proc is not None:
            self._processes.pop(elf_file, None)
        proc = self._spawn(elf_file)
        if proc is not None:
            self._processes[elf_file] = proc
        return proc

    def _terminate_all(self) -> None:
        for proc in list(self._processes.values()):
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            except Exception:
                pass
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        self._processes.clear()

    def decode_address(self, line: bytes) -> str:
        """
        Find executable addresses in a line and translate them to source locations using addr2line.
        **Deprecated**: Method preserved for esp-idf-monitor < 1.7 compatibility - use `translate_addresses` instead.
        :return: A string containing human-readable addr2line output for the addresses found in the line.
        """

        # Translate any addresses found in the line to their source locations
        decoded = self.translate_addresses(line.decode(errors='ignore'))
        if not decoded:
            return ''

        # Synthesize the output of addr2line --pretty-print, while preserving improvements from translate_addresses
        # which relies on the non pretty-print output of addr2line.

        # `decoded` contains [(0x40376121, [(func, path, line), ...]), ...]
        # Which gets converted to:
        # 0x40376121: func at path:line

        def format_trace_entry(location: PcAddressLocation):
            if location.path == 'ROM':
                return f'{location.func} in ROM'

            return f'{location.func} at {location.path}' + (f':{location.line}' if location.line else '')

        out = ''
        # For each address and its corresponding trace
        for addr, trace in decoded:
            # Append address
            out += f'{addr}: '
            if not trace:
                out += '(unknown)\n'
                continue

            # Append first trace entry
            out += f'{format_trace_entry(trace[0])}\n'

            # Any subsequent entries indicate inlined functions
            for entry in trace[1:]:
                out += f' (inlined by) {format_trace_entry(entry)}\n'

        return out

    def translate_addresses(self, line: str) -> List[Tuple[str, List[PcAddressLocation]]]:
        """
        Find executable addresses in a line and translate them to source locations using addr2line.
        :param line: The line to decode, as a string.
        :return: List of addresses and their source locations (with multiple locations indicating an inlined function).
        """

        # === Example input line ===
        # Backtrace: 0x40376121:0x3fcb5590 0x40384ef9:0x3fcb55b0 0x4202c8c9:0x3fcb55d0
        # Each pair represents a program counter (PC) address and a stack pointer (SP) address.
        # We parse them and look them up in the first ELF that owns them.

        addresses = [a.lower() for a in re.findall(ADDRESS_RE, line)]
        if not addresses:
            return []

        out: List[Tuple[str, List[PcAddressLocation]]] = []
        for addr in addresses:
            for matcher in self.pc_address_matcher:
                if not matcher.is_executable_address(int(addr, 16)):
                    continue
                is_rom = matcher.elf_path == self.rom_elf_file
                trace = self.lookup_address(addr, matcher.elf_path, is_rom=is_rom)
                if trace is not None:
                    out.append((addr, trace))
                    # Stop at the first ELF that owns this address.
                    break
        return out

    def lookup_address(
        self,
        address: str,
        elf_file: str,
        is_rom: bool = False,
    ) -> Optional[List[PcAddressLocation]]:
        """
        Translate one executable address to a source location trace using a persistent addr2line.
        :param address: The address to translate (e.g. '0x40376121').
        :param elf_file: The ELF file to use for translating.
        :param is_rom: If True, replace '??' paths with 'ROM' as paths are not available from ROM ELF files.
        :return: List of source locations (with multiple indicating an inlined function), or None if
                 addr2line could not resolve the address (all entries are ??/??).
        """
        proc = self._get_process(elf_file)
        if proc is not None and proc.stdin is not None and proc.stdout is not None:
            try:
                # Write address + sentinel; flush so addr2line sees them immediately.
                proc.stdin.write(f'{address}\n{ADDR2LINE_SENTINEL_INPUT}\n')
                proc.stdin.flush()

                # Accumulate lines until the 3-line sentinel response appears.
                buf = ''
                while True:
                    line = proc.stdout.readline()
                    if line == '':
                        # EOF — process died.
                        raise BrokenPipeError('addr2line closed stdout unexpectedly')
                    buf += line
                    match = ADDR2LINE_SENTINEL_RE.search(buf)
                    if match:
                        # Everything before the sentinel response is the real output for `address`.
                        return _parse_single_address_output(buf[:match.start()], is_rom=is_rom)
            except (BrokenPipeError, OSError, RuntimeError) as err:
                red_print(f'{self.toolchain_prefix}addr2line ({elf_file}): {err}')
                # Drop the dead process; fall through to one-shot below.
                self._processes.pop(elf_file, None)
                try:
                    proc.kill()
                except Exception:
                    pass

        # One-shot fallback (also the path when spawning failed).
        cmd = [f'{self.toolchain_prefix}addr2line', '-fiaC', '-e', elf_file, address]
        try:
            output = subprocess.check_output(cmd, cwd='.')
        except OSError as err:
            red_print(f'{" ".join(cmd)}: {err}')
            return None
        except subprocess.CalledProcessError as err:
            red_print(f'{" ".join(cmd)}: {err}')
            red_print('ELF file is missing or has changed, the build folder was probably modified.')
            return None

        return _parse_single_address_output(output.decode(errors='ignore'), is_rom=is_rom)

    def perform_addr2line(
        self,
        addresses: List[str],
        elf_file: str,
        is_rom: bool = False,
    ) -> Dict[str, List[PcAddressLocation]]:
        """
        Translate a list of executable addresses to source locations using addr2line.
        Thin batched wrapper over :py:meth:`lookup_address` — kept for backwards compatibility.
        :param addresses: List of addresses to translate.
        :param elf_file: The ELF file to use for translating.
        :param is_rom: If True, replace '??' paths with 'ROM' as paths are not available from ROM ELF files.
        :return: Map from each resolved address to its trace (unresolved addresses are omitted).
        """
        out: Dict[str, List[PcAddressLocation]] = {}
        for addr in addresses:
            trace = self.lookup_address(addr, elf_file, is_rom=is_rom)
            if trace is not None:
                out[addr] = trace
        return out

    @staticmethod
    def parse_addr2line_output(
        output: str,
        is_rom: bool = False,
    ) -> Dict[str, List[PcAddressLocation]]:
        """
        Parse the output of addr2line.
        :param output: The output of addr2line as a string.
        :param is_rom: If True, replace '??' paths with 'ROM' as paths are not available from ROM ELF files.
        :return: Map from each address to a list of its source locations (with multiple indicating an inlined function).
        """

        # == addr2line output example ==
        # 0xabcd1234  # Aad # First input address
        # foo()       # A0f # Function
        # foo.c:123   # A0p # Source location
        # 0x1234abcd  # Bad # Second input address
        # inlined()   # B0f # Inlined function
        # bar.c:456   # B0p # Source location
        # bar()       # B1f # Function which inlined inlined()
        # bar.c:789   # B1p # Source location
        # ...         # ... # ... more entries

        # Step 1: Split into sections representing each address and its trace (A**, B**)
        sections = re.split(ADDR2LINE_ADDRESS_LOOKAHEAD_RE, output)

        result: Dict[str, List[PcAddressLocation]] = {}
        for section in sections:
            section = section.strip() # Remove trailing newline
            if not section:
                continue

            # Step 2: Split the section by newlines (Aad, A0f, A0p)
            lines = section.split('\n')

            # Step 3: First line is the address (Aad)
            address = lines[0].strip()

            # Step 4: Build trace by consuming lines in pairs (A0f + A0p)
            #         Multiple entries indicate inlined functions (B0f + B0p, B1f + B1p, etc.)
            trace: List[PcAddressLocation] = []
            valid = False
            for func, path_line in zip(map(str.strip, lines[1::2]), map(str.strip, lines[2::2])):
                path_match = ADDR2LINE_FILE_LINE_RE.match(path_line)
                path = path_match.group('file') if path_match else path_line
                line = path_match.group('line') if path_match else ''

                # If any entry's function or path are present the trace is valid
                # Otherwise if none of the entries are valid, we skip this address
                valid = valid or func != '??' or path != '??'

                # ROM ELF files do not provide paths, so we replace '??' with 'ROM'
                if path == '??' and is_rom:
                    path = 'ROM'

                # Add the trace entry
                trace.append(PcAddressLocation(func, path, line))

            # Step 5: Store the address and its trace in result (if valid and contains entries), go to next section
            if valid and trace:
                result[address] = trace

        return result


def _parse_single_address_output(
    output: str,
    is_rom: bool = False,
) -> Optional[List[PcAddressLocation]]:
    """
    Parse the addr2line output corresponding to a single input address.
    The first line is the echoed input address (discarded — caller knows what it sent).
    The remaining lines are (func, file:line) pairs, one per stack frame (1 + inlines).
    Returns None when the address could not be resolved (every entry is ??/??).
    """
    lines = [ln for ln in output.split('\n') if ln != '']
    if len(lines) < 3:
        return None

    trace: List[PcAddressLocation] = []
    valid = False
    # Skip the echoed address (lines[0]); consume the rest as (func, path_line) pairs.
    for func, path_line in zip(map(str.strip, lines[1::2]), map(str.strip, lines[2::2])):
        path_match = ADDR2LINE_FILE_LINE_RE.match(path_line)
        path = path_match.group('file') if path_match else path_line
        line = path_match.group('line') if path_match else ''

        valid = valid or func != '??' or path != '??'

        if path == '??' and is_rom:
            path = 'ROM'

        trace.append(PcAddressLocation(func, path, line))

    return trace if valid and trace else None
