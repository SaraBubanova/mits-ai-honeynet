#!/usr/bin/env python3
"""
split_pcaps_by_day.py -- split/merge pcap files into one file per calendar day.

Reads one or more classic pcap files (micro- or nanosecond, little- or
big-endian) and writes one output pcap per day: all packets that fall on the
same calendar day (in the chosen timezone) are merged into a single file,
sorted by timestamp. The pcap global header (linktype, snaplen) is preserved.

Usage:
    python3 split_pcaps_by_day.py INPUT [INPUT ...] -o OUTDIR [--tz ZONE]

    INPUT   pcap file(s) and/or directories (directories are scanned for *.pcap)
    -o      output directory (created if missing); files are named YYYY-MM-DD.pcap
    --tz    timezone for day boundaries (IANA name, e.g. Europe/Amsterdam).
            Default: UTC. Use --tz LOCAL for the machine's local timezone.

Examples:
    python3 split_pcaps_by_day.py pcaps/ -o pcaps_by_day/
    python3 split_pcaps_by_day.py capture1.pcap capture2.pcap -o out/ --tz Europe/Amsterdam

Note: pcapng files are not supported (this tool handles classic pcap only).
"""

import argparse
import os
import struct
import sys
from datetime import datetime, timezone

# magic -> (struct endian prefix, timestamp fraction divisor)
PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),  # microsecond, little-endian
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),  # microsecond, big-endian
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),  # nanosecond, little-endian
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),  # nanosecond, big-endian
}
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


def iter_packets(path):
    """Yield (ts_float, record_header_bytes, packet_bytes, global_header) per packet."""
    with open(path, 'rb') as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError(f'{path}: file too small to be a pcap')
        magic = header[:4]
        if magic == PCAPNG_MAGIC:
            raise ValueError(f'{path}: pcapng format is not supported, only classic pcap')
        if magic not in PCAP_MAGICS:
            raise ValueError(f'{path}: not a classic pcap file (bad magic {magic.hex()})')
        endian, div = PCAP_MAGICS[magic]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig = struct.unpack(endian + 'IIII', rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                print(f'warning: {path}: truncated trailing packet dropped '
                      f'(header declares {incl_len} bytes, only {len(data)} present)',
                      file=sys.stderr)
                break
            yield ts_sec + ts_frac / div, rec, data, header


def resolve_tz(name):
    if name.upper() == 'UTC':
        return timezone.utc
    if name.upper() == 'LOCAL':
        return None  # None -> use system local time
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception as e:
        sys.exit(f'error: cannot use timezone {name!r} ({e}). '
                 f'Use an IANA name like Europe/Amsterdam, UTC, or LOCAL.')


def day_of(ts, tz):
    dt = datetime.fromtimestamp(ts, tz) if tz else datetime.fromtimestamp(ts)
    return dt.date().isoformat()


def collect_inputs(args):
    files = []
    for a in args:
        if os.path.isdir(a):
            found = sorted(
                os.path.join(a, f) for f in os.listdir(a)
                if f.lower().endswith(('.pcap', '.cap'))
            )
            if not found:
                print(f'warning: no .pcap/.cap files in directory {a}', file=sys.stderr)
            files.extend(found)
        elif os.path.isfile(a):
            files.append(a)
        else:
            print(f'warning: skipping {a!r}, not a file or directory', file=sys.stderr)
    return files


def main():
    ap = argparse.ArgumentParser(description='Split/merge pcap files into one file per calendar day.')
    ap.add_argument('inputs', nargs='+', help='pcap files and/or directories containing pcaps')
    ap.add_argument('-o', '--outdir', required=True, help='output directory for YYYY-MM-DD.pcap files')
    ap.add_argument('--tz', default='UTC',
                    help="timezone for day boundaries: IANA name (Europe/Amsterdam), UTC (default), or LOCAL")
    args = ap.parse_args()

    tz = resolve_tz(args.tz)
    files = collect_inputs(args.inputs)
    if not files:
        sys.exit('error: no input pcap files found')

    os.makedirs(args.outdir, exist_ok=True)

    # day -> {'header': bytes, 'linktype': int, 'packets': [(ts, rec, data)]}
    days = {}
    total_in = 0
    for path in files:
        n = 0
        first = last = None
        for ts, rec, data, header in iter_packets(path):
            day = day_of(ts, tz)
            d = days.setdefault(day, {'header': header, 'packets': []})
            if d['header'] != header:
                print(f'warning: {path} has a different pcap header than the first file for '
                      f'{day}; keeping the first header (linktype may differ)', file=sys.stderr)
            d['packets'].append((ts, rec, data))
            if first is None:
                first = ts
            last = ts
            n += 1
        total_in += n
        fmt = '%Y-%m-%d %H:%M:%S'
        print(f'  read {path}: {n} packets, '
              f'{datetime.fromtimestamp(first, tz).strftime(fmt) if tz else datetime.fromtimestamp(first).strftime(fmt)}'
              f' -> '
              f'{datetime.fromtimestamp(last, tz).strftime(fmt) if tz else datetime.fromtimestamp(last).strftime(fmt)}')

    total_out = 0
    for day in sorted(days):
        packets = sorted(days[day]['packets'], key=lambda p: p[0])
        out_path = os.path.join(args.outdir, f'{day}.pcap')
        with open(out_path, 'wb') as out:
            out.write(days[day]['header'])
            for _ts, rec, data in packets:
                out.write(rec)
                out.write(data)
        total_out += len(packets)
        t0, t1 = packets[0][0], packets[-1][0]
        show = (lambda t: datetime.fromtimestamp(t, tz).strftime('%Y-%m-%d %H:%M:%S')) if tz \
            else (lambda t: datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S'))
        print(f'  wrote {out_path}: {len(packets)} packets, {show(t0)} -> {show(t1)}')

    print(f'done: {total_in} packets in -> {total_out} packets out, '
          f'{len(days)} day file(s) in {args.outdir}/')
    if total_in != total_out:
        print('warning: packet count mismatch!', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
