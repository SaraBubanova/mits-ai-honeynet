import json
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

MAX_WORKERS = 4

def find_cves(signature):
  return [w.strip('(.,);') for w in signature.split() if 'CVE-' in w]

def cve_by_ip(file_path):
  ip_data = {}

  try:
    with open(file_path, 'r') as f:
      for line in f:
        line = line.strip()
        if not line:
          continue
        try:
          event = json.loads(line)
        except json.JSONDecodeError:
          continue

        if event.get('event_type') != 'alert':
          continue

        src_ip   = event.get('src_ip')
        dst_port = event.get('dest_port')
        signature = event.get('alert',{}).get('signature','')

        if not (src_ip and dst_port and signature):
          continue

        metadata = event.get('alert', {}).get('metadata', {})
        meta_cves = [str(cve).replace('_', '-').upper() for cve in metadata.get('cve', [])] # Same format as reported under signature
        
        cves = list(set(find_cves(signature) + meta_cves))

        if not cves:
          continue
        
        for cve in cves:
          ip_data.setdefault(src_ip, {}).setdefault(cve, {'dst_ports': set(), 'count': 0})
          ip_data[src_ip][cve]['dst_ports'].add(dst_port)
          ip_data[src_ip][cve]['count'] += 1

    return ip_data
  
  except Exception as e:
    print(f"Error: {e}")
    return {}


def merge_ip(old, new):
  for ip, cves in new.items():
    if ip not in old:
      old[ip] = cves
    else:
      for cve, data in cves.items():
        if cve not in old[ip]:
          old[ip][cve] = data
        else:
          old[ip][cve]['dst_ports'].update(data['dst_ports'])
          old[ip][cve]['count'] += data['count']



def process_all(suricata_files):
  ip_data = {}

  with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
    cve_futures   = {executor.submit(cve_by_ip, f): f for f in suricata_files}
    for future in as_completed(cve_futures):
      f = cve_futures[future]
      try:
        merge_ip(ip_data, future.result())
        print(f"Succesfully processed IP {f.name}")
      except Exception as e:
        print(f"Failed IP {f.name}: {e}")

  output = {}
  for ip, cves in ip_data.items():
    output[ip] = {}

    for cve, info in cves.items():
      output[ip][cve] = {
        'count': info['count'],
        'dst_ports': sorted(info['dst_ports'])
      }

  # JSON export (same as before)
  out = Path("results")
  out.mkdir(exist_ok=True)
  (out / 'suricata_cve.json').write_text(json.dumps(output, indent=2))

  return output

def print_summary(ip_data):
  cve_totals = {}
  for cves in ip_data.values():
    for cve, info in cves.items():
      cve_totals[cve] = cve_totals.get(cve, 0) + info['count']

  print("\nCVE count:\n")
  for cve, count in sorted(cve_totals.items(), key=lambda x: -x[1]):
    print(f"{cve}: {count}")

if __name__ == "__main__":
  eve_files = sorted(Path("samples").rglob("eve*.json*"))
  print(f"{len(eve_files)} file(s) to process\n")
 
  ip_data = process_all(eve_files)
  print_summary(ip_data)
