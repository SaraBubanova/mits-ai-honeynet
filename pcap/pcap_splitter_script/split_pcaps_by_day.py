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
import heapq
import os
import shutil
import struct
import sys
import tempfile
from datetime import datetime, timezone

# magic -> (struct endian prefix, timestamp fraction divisor)
PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),  # microsecond, little-endian
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),  # microsecond, big-endian
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),  # nanosecond, little-endian
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),  # nanosecond, big-endian
}
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

# Some datasets are anonymised: timestamps count from zero (1970) instead of the real
# capture time, so splitting by day is meaningless. Anything earlier than this is suspect.
MIN_REAL_TS = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()


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
            # Same rule as pcap_analysis.py: any name containing ".pcap" counts,
            # so rotated files like "log.pcap.43235343" are found. Subfolders too.
            found = sorted(
                os.path.join(root, f)
                for root, _dirs, names in os.walk(a)
                for f in names
                if '.pcap' in f.lower() or f.lower().endswith('.cap')
            )
            if not found:
                print(f'warning: no .pcap/.cap files in directory {a}', file=sys.stderr)
            files.extend(found)
        elif os.path.isfile(a):
            files.append(a)
        else:
            print(f'warning: skipping {a!r}, not a file or directory', file=sys.stderr)
    return files


def fmt_ts(ts, tz):
    dt = datetime.fromtimestamp(ts, tz) if tz else datetime.fromtimestamp(ts)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def read_run(path, endian, div):
    """Yield (ts, record_header, packet_bytes) from a spilled run file."""
    with open(path, 'rb') as f:
        while True:
            rec = f.read(16)
            if not rec:
                return
            ts_sec, ts_frac, incl_len, _orig = struct.unpack(endian + 'IIII', rec)
            yield ts_sec + ts_frac / div, rec, f.read(incl_len)


def sorted_run(run):
    """Return an iterator over one run in timestamp order.

    Captures are normally written in time order, so a run is just streamed
    from disk. If a run has out-of-order packets (flagged while spilling) it is
    sorted in memory first; that costs at most one input file's share of one day.
    """
    packets = read_run(run['path'], run['endian'], run['div'])
    if run['in_order']:
        return packets
    return iter(sorted(packets, key=lambda p: p[0]))


def split_by_day(inputs, outdir, tz_name='UTC'):
    """Split/merge the pcaps in `inputs` (files and/or folders) into OUTDIR/YYYY-MM-DD.pcap.

    Raises ValueError if no pcap files are found and RuntimeError if the packet
    counts going in and out differ. Can be imported, e.g. by pcap_analysis.py.
    """
    tz = resolve_tz(tz_name)
    files = collect_inputs(inputs)
    if not files:
        raise ValueError('no input pcap files found')

    os.makedirs(outdir, exist_ok=True)

    # Memory use stays small: packets are streamed to temporary "run" files on
    # disk (one per day and input file), then each day is built by merging its runs.
    # The temp folder sits inside OUTDIR so it uses the same disk as the output.
    tmp_dir = tempfile.mkdtemp(prefix='.split_runs_', dir=outdir)
    try:
        suspect_files = []   # inputs whose timestamps look anonymised
        day_header = {}   # day -> pcap global header of the first file seen for that day
        day_runs = {}     # day -> [run dict, ...] in input order
        total_in = 0

        for file_no, path in enumerate(files):
            n = 0
            first = last = None
            handles = {}  # day -> open run file, for this input file only
            runs = {}     # day -> run dict, for this input file only
            try:
                for ts, rec, data, header in iter_packets(path):
                    day = day_of(ts, tz)
                    if day not in handles:
                        run_path = os.path.join(tmp_dir, f'{day}_{file_no:05d}.run')
                        handles[day] = open(run_path, 'wb')
                        endian, div = PCAP_MAGICS[header[:4]]
                        runs[day] = {'path': run_path, 'endian': endian, 'div': div,
                                     'in_order': True, 'last_ts': None}
                        day_runs.setdefault(day, []).append(runs[day])
                        if day not in day_header:
                            day_header[day] = header
                        elif day_header[day] != header:
                            print(f'warning: {path} has a different pcap header than the first file for '
                                  f'{day}; keeping the first header (linktype may differ)', file=sys.stderr)
                    run = runs[day]
                    if run['last_ts'] is not None and ts < run['last_ts']:
                        run['in_order'] = False
                    run['last_ts'] = ts
                    handles[day].write(rec)
                    handles[day].write(data)
                    if first is None:
                        first = ts
                    last = ts
                    n += 1
            finally:
                for h in handles.values():
                    h.close()
            total_in += n
            if n:
                print(f'  read {path}: {n} packets, {fmt_ts(first, tz)} -> {fmt_ts(last, tz)}')
                if first < MIN_REAL_TS:
                    suspect_files.append(path)
                    print(f'WARNING: {path} starts at {fmt_ts(first, tz)}. The timestamps look '
                          f'anonymised or relative, so the dates are not real.', file=sys.stderr)
            else:
                print(f'  read {path}: 0 packets')

        total_out = 0
        for day in sorted(day_runs):
            out_path = os.path.join(outdir, f'{day}.pcap')
            count = 0
            t0 = t1 = None
            streams = [sorted_run(r) for r in day_runs[day]]
            with open(out_path, 'wb') as out:
                out.write(day_header[day])
                # heapq.merge keeps only one packet per run in memory; ties keep input order
                for ts, rec, data in heapq.merge(*streams, key=lambda p: p[0]):
                    out.write(rec)
                    out.write(data)
                    if t0 is None:
                        t0 = ts
                    t1 = ts
                    count += 1
            total_out += count
            print(f'  wrote {out_path}: {count} packets, {fmt_ts(t0, tz)} -> {fmt_ts(t1, tz)}')
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print(f'done: {total_in} packets in -> {total_out} packets out, '
          f'{len(day_runs)} day file(s) in {outdir}/')
    if suspect_files:
        print(f'WARNING: {len(suspect_files)} input file(s) have timestamps before 2000, so the '
              f'day split is not meaningful for them. See the warnings above.', file=sys.stderr)
    if total_in != total_out:
        raise RuntimeError(f'packet count mismatch: {total_in} in, {total_out} out')


def main():
    ap = argparse.ArgumentParser(description='Split/merge pcap files into one file per calendar day.')
    ap.add_argument('inputs', nargs='+', help='pcap files and/or directories containing pcaps')
    ap.add_argument('-o', '--outdir', required=True, help='output directory for YYYY-MM-DD.pcap files')
    ap.add_argument('--tz', default='UTC',
                    help="timezone for day boundaries: IANA name (Europe/Amsterdam), UTC (default), or LOCAL")
    args = ap.parse_args()
    try:
        split_by_day(args.inputs, args.outdir, args.tz)
    except (ValueError, RuntimeError) as e:
        sys.exit(f'error: {e}')


if __name__ == '__main__':
    main()
