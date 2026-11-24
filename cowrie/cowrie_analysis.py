import time
import os
import json
import requests
import statistics
import re
from pathlib import Path
from prefixspan import PrefixSpan
from concurrent.futures import ProcessPoolExecutor, as_completed
from dotenv import load_dotenv, find_dotenv
from datetime import datetime
from collections import Counter

MAX_WORKERS = 4

load_dotenv(find_dotenv())

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "none")
ABUSEIPDB_CACHE = Path("results/abuseipdb_cache.json")
ABUSEIPDB_ATTEMPTS = 1000 # Maximum of 1000 with the free subscription
API_URL = "https://api.abuseipdb.com/api/v2/check"

# Based initially on https://github.com/EfeEmirYuce/Cowrie_Honeypot_Log_Analysis_Engine/blob/main/analysis.py
KEYWORDS = {
  # Recon: system fingerprinting commands.
  # Sethuraman et al. (2023): "attackers unanimously run uname -a" recon is seen almost as universal and insufficient alone to distinguish skill level.
  'recon': [
    'uname', 'whoami', 'id', 'hostname', 'ifconfig', 'ip a', 'netstat', 'ps', 'top', 'w', 'who', 'last', 'free -m', 'df -h', 
    'lscpu', 'nproc', 'cat /proc/cpuinfo', 'cat /etc/passwd', 'echo Hi | cat -n',
  ],

  # Download: deployment.
  # Karaarslan et al. (2025): "If a session contains wget or curl, then classify the intent as Malware Deployment."
  'download': ['wget', 'curl', 'tftp', 'ftpget', 'scp', 'yum install', 'apt install'],

  # Persistence: mechanisms to maintain access.
  # Koniaris et al. (2013): observed attackers modifying .ssh/authorized_keys to maintain return access. 
  # Munteanu et al. (2025): persistence mechanisms including crontab observed across long-term SSH honeynet deployment.
    'persistence': [
    'authorized_keys', 'crontab -e', 'crontab /', 'crontab <', 'systemctl', '/etc/init.d',
    'chattr', '.ssh', 'lockr -ia', '/ip cloud print',
  ],

  # Cleanup: covering tracks.
  # Vusal (2010): "almost all of the observed hackers cleaned their tracks" used as the primary indicator distinguishing hackers from script kiddies 
  # (Hackers were refered as high skilled actors).
  'cleanup': ['history -c', 'rm -rf', 'pkill', 'unset'],

  # Password change: human awareness of session state.
  # Koniaris et al. (2013): "a small number of attackers gained access manually, as they changed the password once in by using passwd,
  # which allows them to return and prevents other attackers from accessing the system. They consider this to be a human driven activity
  # as they are aware of the state of the session."
  'password_change': ['passwd', 'chpasswd'],

  # Privilege escalation.
  # Koniaris et al. (2013): "some users used chmod +x, which extends execution rights to users. They combined this with previously
  # downloaded files to run malicious scripts on the system.
  'privilege': ['chmod', 'chown', 'sudo'],

  # Execution: running downloaded or local scripts.
  # Koniaris et al. (2013): Used to run previously downloaded malicious scripts on the system; bash/sh are the often executed after download
  'execution': ['bash ', ' sh ', 'perl'],

  # Malicious files: known cryptominer / botnet artefacts.
  # Var Naseri et al. (2026): identified xmr.sh and miner binaries as the primary payload indicators in cryptomining sessions
  # across 410,000 Cowrie attack sessions.
  'malicious_files': ['[Mm]iner', '/var/run/gcc.pid'],

  # Lateral movement: access to other systems.
  # Vusal (2010): observed attackers attempting to access other systems after gaining access, using the compromised host as a 'launchpad'.
  'lateral': ['ssh ', 'scp ', 'rsync'],
}

BOTNET_SIGNATURES = [
  'mdrfckr', # Outlaw/Shellbot SSH key injection signature
]

# CV < 0.5; Session durations are statistically consistent.
# Balogh et al. (2025): "Shorter intervals between attacks may suggest a more experienced attacker, while longer gaps could indicate a novice.
# Extremely brief intervals might reveal that the attack originates from a bot or script."
# These justify using timing consistency as a bot signal. The CV metric and 0.5 threshold are methodological choices
CV_THRESHOLD = 0.5
 
# command_variety < 0.15; fewer than 15 % of commands are unique = Highly repetitive.
# Chacon et al. (2020) citing Kemppainen et al.: bots are identified through "command timestamp consistency and delay between
# commands, command execution despite errors in the previous command, and detecting the same command executed over separate sessions."
# The threshold has no direct empirical basis.
REPETITION_THRESHOLD = 0.15
 
# Minimum activity before assigning intermediate / advanced (Works overall across the IP).
# Karaarslan et al. (2025): "Shallow Probe with 1 or 2 commands before disconnecting"
MIN_COMMANDS_MEANINGFUL = 3
 
# Command Volume: many sessions, almost no commands in each session.
# Balogh et al. (2024): "An attacker who executes a few attacks within seconds against a specific protocol using an attack script may likely
# be automated or a bot."
# Savage et al. (2025): Cluster 0 across all three honeypot systems consists of "quick probes (one or two sessions)" scanner behaviour.
# Karaarslan et al. (2025): "Shallow Probe" with 1 or 2 commands before disconnecting
# Note: no universal empirical threshold exists for these parameters; the values are tunable based session distribution from the Cowrie Logs.
BOT_MIN_SESSIONS = 5
BOT_MAX_CMDS_PER_SESSION = 3

def load_cache():
  if ABUSEIPDB_CACHE.exists():
    return json.loads(ABUSEIPDB_CACHE.read_text())
  return {}

def save_cache(cache):
  ABUSEIPDB_CACHE.parent.mkdir(exist_ok=True)
  ABUSEIPDB_CACHE.write_text(json.dumps(cache, indent=2))

# Chacon et al. (2020): bot detection targets semantic repetition across sessions. Credentials and keys are randomised
# per session by automated tools but the underlying command structure is identical.
def normalise_command(cmd):
  # Normalise chpasswd/passwd
  cmd = re.sub(r'echo "[^"]*"\|chpasswd', 'echo "REDACTED"|chpasswd', cmd)
  cmd = re.sub(r'echo -e "[^"]*"\|passwd', 'echo -e "REDACTED"|passwd', cmd)

  # Normalise ssh public keys injection
  cmd = re.sub(r'ssh-rsa\s+\S+', 'ssh-rsa REDACTED', cmd)
  return cmd

def query_abuseipdb(ip, cache):
  if ip in cache:
    return cache[ip]
  
  # Refer to https://docs.abuseipdb.com/?python#check-endpoint
  headers = {
    "Accept": "application/json",
    "Key": ABUSEIPDB_KEY,
  }

  params = {
    "ipAddress": ip,
    "maxAgeInDays": 365,
    "verbose": True,
  }

  result = None
  try:
    response = requests.get(API_URL, headers=headers, params=params)
    response.raise_for_status()
    data = response.json()["data"]

    result = {
      "abuseConfidenceScore":data["abuseConfidenceScore"],
      "totalReports":data["totalReports"],
      "countryCode":data["countryCode"],
      "isp":data["isp"],
      "domain":data["domain"],
      "isWhitelisted":data["isWhitelisted"],
      "lastReportedAt":data["lastReportedAt"],
      "reports":data.get("reports",[]), # reports may be empty and there may be multiple
    }
  except Exception as e:
    print(f"Error when calling ABUSEIPDB for {ip}: {e}")
    result = None

  cache[ip] = result
  return result

# Sequential, given attempts are limited would not do it in parallel
def enrich_with_abuseipdb(ip_data, max_queries=ABUSEIPDB_ATTEMPTS):
  cache = load_cache()

  uncached = []
  for ip in ip_data:
    if ip not in cache:
      uncached.append(ip)

  print(f"{len(cache)}/{len(ip_data)} IPs in cache")

  if max_queries is not None: 
    uncached = uncached[:max_queries] # Limit the query to max_queries
    print(f"Limit set to {max_queries} queries in this run")
  
  i = 0
  for ip in uncached:
    query_abuseipdb(ip, cache)
    if (i + 1) % 10 == 0:
      save_cache(cache)
      print(f"{i+1}/{len(uncached)} queried")
    i += 1
    time.sleep(1)

  save_cache(cache)

  # Aggregate ABUSEIPDB data to the IPs that have been processed
  for ip, data in ip_data.items():
    data["abuse"] = cache.get(ip)

  return ip_data

def session_by_ip(file_path):
  ip_data = {}
  session_timing = {}
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
        
        eventid = event.get('eventid')
        session = event.get('session')
        timestamp = event.get('timestamp')

        if session and timestamp:
          if eventid == 'cowrie.session.connect':
            session_timing.setdefault(session, {})['start'] = timestamp
          elif eventid == 'cowrie.session.closed':
            time = session_timing.setdefault(session, {})
            time.setdefault('end', timestamp)
            time['duration_seconds'] = event.get('duration')

        if eventid not in ('cowrie.command.input', 'cowrie.command.failed'):
          continue

        if not (event.get('src_ip') and event.get('input')):
          continue
        
        src_ip = event['src_ip']
        command = event['input']
        ip_data.setdefault(src_ip, {}).setdefault(session, []).append((timestamp, command))
  
    result = {}
    for ip, sessions in ip_data.items():
      total_commands = sum(len(c) for c in sessions.values())
      result[ip] = {
        'total_commands': total_commands,
        'total_sessions': len(sessions),
        'sessions': sessions,
        'session_timing': {s: session_timing.get(s, {}) for s in sessions}
      }
    return result

  except Exception as e:
    print(f"Error: {e}")
    return {}

def credentials_per_session(file_path):
  credentials_data = {}
  
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
        
        # Validate event type and required fields
        if event.get('eventid') not in ('cowrie.login.success', 'cowrie.login.failed'):
          continue

        if not (event.get('session') and event.get('username') and event.get('password')):
          continue
        
        session = event.get('session')
        username = event.get('username')
        password = event.get('password')
        
        # Dictionary structure: { session: [ { username, password } ] }
        if session not in credentials_data:
          credentials_data[session] = []
        
        credentials_data[session].append({
          'username': username,
          'password': password
        })
    
    # # JSON export
    # out_path = Path("samples") / 'credentials_per_session.json'
    # out_path.parent.mkdir(parents=True, exist_ok=True)
    # with out_path.open('w') as f:
    #   json.dump(credentials_data, f, indent=2)
    
    # print(f"Total number of login attempts: {sum(len(s) for s in credentials_data.values())}")
    
    return credentials_data
    
  except Exception as e:
    print(f"Error: {e}")
    return {}

def merge_ip(old, new):
  for ip, data in new.items():
    if ip not in old:
      old[ip] = data
    else:
      for session_id, commands in data['sessions'].items():
        if session_id not in old[ip]['sessions']: # Session did not exist
          old[ip]['sessions'][session_id] = commands
          old[ip]['session_timing'][session_id] = data['session_timing'].get(session_id, {})
          old[ip]['total_sessions'] += 1
        else: # Session did exist
          old[ip]['sessions'][session_id].extend(commands)
        old[ip]['total_commands'] += len(commands)


def process_all(cowrie_files):
  ip_data = {}
  cred_data = {}

  with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
     # Submit a task to process each task for ip and credentials aggregation to the pool of workers
    ip_futures   = {executor.submit(session_by_ip, f): f for f in cowrie_files}
    cred_futures = {executor.submit(credentials_per_session, f): f for f in cowrie_files}
    for future in as_completed(ip_futures):
      f = ip_futures[future]
      try:
        merge_ip(ip_data, future.result())
        print(f"Succesfully processed IP {f.name}")
      except Exception as e:
        print(f"Failed IP {f.name}: {e}")
    for future in as_completed(cred_futures):
      f = cred_futures[future]
      try:
        cred_data.update(future.result())
        print(f"Succesfully processed Credential {f.name}")
      except Exception as e:
        print(f"Failed Credential {f.name}: {e}")

  # Enrich data before exporting to store in session_per_ip.json
  ip_data = enrich_with_abuseipdb(ip_data)
  # JSON export (same as before)
  out = Path("results")
  out.mkdir(exist_ok=True)
  (out / 'session_per_ip.json').write_text(json.dumps(ip_data, indent=2))
  (out / 'credentials_per_session.json').write_text(json.dumps(cred_data, indent=2))

  print(f"Total unique IPs: {len(ip_data)}")
  print(f"Total login attempts: {sum(len(s) for s in cred_data.values())}")
  
  return ip_data, cred_data

def run_prefixspan(ip_commands, min_support_pct, normalise):
  sequences = []
  for data in ip_commands.values():
    for commands in data['sessions'].values():
      if commands:
        if normalise:
          session_cmds = [normalise_command(cmd) for _, cmd in commands]
        else:
          session_cmds = [cmd for _, cmd in commands]
        sequences.append(session_cmds)
  
  n = len(sequences)
  min_support = int(min_support_pct * n)
  
  print(f"Total sequences: {n}")
  print(f"Min support: {min_support}")
  
  ps = PrefixSpan(sequences)
  patterns = ps.frequent(min_support, closed=True)
  patterns.sort(key=lambda x: x[0], reverse=True)
  return patterns, n

# Chacon et al. (2020) citing Kemppainen et al.: bots are identified through "command timestamp consistency and delay between
# commands, command execution despite errors in the previous command, and detecting the same command executed over separate sessions."
def get_inter_command_intervals(ip):
  all_intervals = []
  for session_commands in ip.get('sessions', {}).values():
    if len(session_commands) < 2:
      continue
    # Sort by timestamp within session
    try:
      sorted_cmds = sorted( session_commands, key=lambda x: x[0] ) # timestamp
      timestamps = [datetime.fromisoformat(ts.replace('Z', '+00:00')) for ts, _ in sorted_cmds]
      intervals = [
        (timestamps[i+1] - timestamps[i]).total_seconds()
        for i in range(len(timestamps) - 1)
        if (timestamps[i+1] - timestamps[i]).total_seconds() >= 0
      ]
      all_intervals.extend(intervals)
    except Exception:
      continue
  if len(all_intervals) < 2:
    return {'cmd_cv': None, 'cmd_median': None, 'cmd_is_consistent': False}
  
  mean   = statistics.mean(all_intervals)
  st_dev = statistics.stdev(all_intervals)
  cv     = st_dev / mean if mean > 0 else None
  
  return {
    'cmd_cv': cv,
    'cmd_median': statistics.median(all_intervals),
    'cmd_is_consistent': cv is not None and cv < CV_THRESHOLD,
  }

def get_timing_features(ip):
  durations   = []
  
  for time in ip.get('session_timing').values():
    duration_seconds = time.get('duration_seconds')
    if duration_seconds is not None:
      durations.append(duration_seconds)

  median_duration = None
  st_dev = None
  is_automated = False
  is_consistent = False
  cv = None

  if durations:
    median_duration = statistics.median(durations)

    if len(durations) > 1:
      st_dev = statistics.stdev(durations)
      mean_duration = statistics.mean(durations)
      cv = st_dev / mean_duration if mean_duration > 0 else None # Coefficient of Variation
      is_consistent = cv is not None and cv < 0.5

    # is_automated = (median_duration < 120) and is_consistent
    is_automated = is_consistent

  return {'is_automated': is_automated, 'median_duration': median_duration, 'st_dev': st_dev, 'cv': cv}

def score_commands(all_commands):
  scores = {key: 0 for key in KEYWORDS}
  for cmd in all_commands:
    for category, keywords in KEYWORDS.items():
      if any(keyword in cmd for keyword in keywords):
        scores[category] += 1
  return scores

def classify_skill(data, timing, ici):
  abuse = data.get("abuse") or {}
  total_commands = data["total_commands"]
  total_sessions = data["total_sessions"]
  commands_per_session = total_commands / max(total_sessions, 1)
  all_commands = [cmd for session in data["sessions"].values() for _, cmd in session]

  normalised_commands  = [normalise_command(cmd) for cmd in all_commands]
  unique_commands = len(set(normalised_commands))
  scores = score_commands(all_commands)
  command_variety = unique_commands / max(total_commands, 1)
  
  # Behavioural FLAGS
  has_recon = scores['recon'] > 0
  has_download = scores['download'] > 0
  has_persistence = scores['persistence'] > 0
  has_passwd_change = scores['password_change'] > 0
  has_lateral = scores['lateral'] > 0
  has_privilege = scores['privilege'] > 0
  has_execution = scores['execution'] > 0
  has_malicious = scores['malicious_files'] > 0

  # Vusal (2010): history -c is the primary track-covering signal that # distinguishes advanced ("hackers") from lower skill levels.
  # rm -rf alone is too common in automated scripts to be discriminating.
  has_cleanup = 'history -c' in ' '.join(all_commands)

  abuse_categories = set(
    cat
    for r in abuse.get("reports", [])
    for cat in r.get("categories", [])
  )
  known_brute   = 18 in abuse_categories
  known_malware = 20 in abuse_categories

  commands_grouped = ' '.join(all_commands)
  if any(sig in commands_grouped for sig in BOTNET_SIGNATURES):
    return "bot"

  # Consistent session lengths indicate scripted behaviou
  sess_consistent = timing.get('is_automated', False)

  # inter-command delays
  ici_consistent = ici.get('cmd_is_consistent', False)

  # Chacon et al. (2020): "detecting the same command executed over separate sessions" is an explicit bot signal.
  cmd_counts = Counter(normalise_command(cmd) for session in data['sessions'].values() for _, cmd in session)
  is_cross_session_repeat = any(count >= 2 for count in cmd_counts.values())

  is_repetitive = command_variety < REPETITION_THRESHOLD
  is_volume_bot = (total_sessions >= BOT_MIN_SESSIONS and commands_per_session <= BOT_MAX_CMDS_PER_SESSION)
  
  # BOT
  # Require 2+ independent signals to reduce false positives.
  # Zuzcak et al. (2020): simple attacker executes predefined repeating commands without reacting to the environment.
  # Munteanu et al. 2025): bot behaviour identified through command pattern regularity across sessions.
  bot_signals = sum([
    sess_consistent, # session durations near identical
    ici_consistent, # intercommand delays near identical
    is_repetitive, # very low number of unique commands
    is_volume_bot, # many sessions, almost no commands each
    is_cross_session_repeat, # same command in 3+ separate sessions
    known_brute, # AbuseIPDB: known bruteforcer
    known_malware, # AbuseIPDB: known infected host
  ])
  if bot_signals >= 2:
    return "bot"
  
  # ACTIVITY GATE, Vusal (2010): manual or automatic distinction requires that attackers carried out activities after breaking in
  has_meaningful_activity = (total_commands >= MIN_COMMANDS_MEANINGFUL)

  if has_meaningful_activity:
    # ADVANCED 
    # Vusal (2010): cleanup (history -c) is the primary marker of advanced actors who deliberately cover their tracks.
    # Koniaris et al. (2013): password change + persistence indicates a human session state awareness. Lateral movement indicates
    # that the host is being used as a launchpad.
    advanced_conditions = [
      (has_recon and has_persistence and has_cleanup, "recon+persistence+cleanup"),
      (has_recon and has_persistence and has_lateral, "recon+persistence+lateral"),
      (has_passwd_change and has_persistence and has_cleanup, "passwd+persistence+cleanup"),
      (has_passwd_change and has_lateral, "passwd+lateral"),
    ]
    for condition, label in advanced_conditions:
      if condition:
        return f"advanced:{label}"
      
    # INTERMEDIATE
    # Balogh et al. (2024): intermediate attackers purposefully use tools and can customise existing scripts.
    # Koniaris et al. (2013): chmod+x combined with downloaded files to run malicious scripts; passwd signals human awareness.
    # Sethuraman et al. (2023): recon alone cannot be used to classify an attacker, so it only qualifies here when paired with a second stage.
    intermediate_conditions = [
      has_download and has_execution,
      has_download and has_privilege,
      has_malicious and has_execution,
      has_persistence and has_cleanup,
      has_passwd_change and has_recon,
    ]
    if any(intermediate_conditions):
      return "intermediate"
    
  # SCRIPT KIDDIE
  # Vusal et al. (2010): uses scripts without understanding them.
  # Karaarslan et al. (2025): shallow probe is the expected dominant class.
  return "script_kiddie"

if __name__ == "__main__":
  cowrie_files = sorted(Path("samples").rglob("cowrie*.json*"))
  print(f"{len(cowrie_files)} files to process\n")

  ip_commands, credentials = process_all(cowrie_files)
  
  classified_output = {}
  for ip, data in ip_commands.items():

    timing = get_timing_features(data)
    is_automated = timing['is_automated']
    median_duration = timing['median_duration']
    st_dev = timing['st_dev']
    cv = timing['cv']
    inter_command_intervals = get_inter_command_intervals(data)

    skill = classify_skill(data, timing, inter_command_intervals)
    abuse = data.get("abuse") or {}
    classified_output[ip] = {
      "skill": skill,
      "median_duration": median_duration,
      "st_dev": st_dev,
      "cv": cv,
      "ici": inter_command_intervals,
      "total_commands": data["total_commands"],
      "total_sessions": data["total_sessions"],
      "abuse_score": abuse.get("abuseConfidenceScore")
    }

  out = Path("results")
  out.mkdir(exist_ok=True)

  (out / "ip_classification.json").write_text(json.dumps(classified_output, indent=2))

  skill_counts = Counter(d['skill'] for d in classified_output.values())
  total = sum(skill_counts.values())

  summary = {
    "total_ips": total,
    "by_skill": {
      skill: {"count": count, "pct": round(100 * count / total, 2)}
      for skill, count in skill_counts.most_common()
    }
  }

  (out / "ip_classification_summary.json").write_text(json.dumps(summary, indent=2))

  print(f"\nTotal IPs classified: {total}")
  for skill, count in skill_counts.most_common():
    print(f"{skill} {count} ({100*count/total:.1f}%)")
  print(f"\n")
  # for pct in [0.001, 0.005, 0.01, 0.05]: # Increase to find more common patterns (Useful for botnet detection)
  #   print(f"\nMin support: {pct*100}%\n")
  #   patterns, n = run_prefixspan(ip_commands, pct)
  #   print(f"Number of patterns found: {len(patterns)}")
  #   for support, pattern in patterns:
  #     pct_sessions = support / n * 100
  #     print(f"\n{pct_sessions:.1f}%): {pattern}")

  # # Unnormalised run
  # with (out / "prefixspan_patterns_raw.txt").open("w", encoding="utf-8") as f:
  #   for pct in [0.001, 0.005, 0.01, 0.05]:
  #     print(f"\nMin support: {pct*100}%\n", file=f)
  #     patterns, n = run_prefixspan(ip_commands, pct, normalise=False)
  #     print(f"Number of patterns found: {len(patterns)}", file=f)
  #     for support, pattern in patterns:
  #       pct_sessions = support / n * 100
  #       print(f"\n{pct_sessions:.1f}%): {pattern}", file=f)
  
  # # Normalised run
  # with (out / "prefixspan_patterns_normalised.txt").open("w", encoding="utf-8") as f:
  #   for pct in [0.001, 0.005, 0.01, 0.05]:
  #     print(f"\nMin support: {pct*100}%\n", file=f)
  #     patterns, n = run_prefixspan(ip_commands, pct, normalise=True)
  #     print(f"Number of patterns found: {len(patterns)}", file=f)
  #     for support, pattern in patterns:
  #       pct_sessions = support / n * 100
  #       print(f"\n{pct_sessions:.1f}%): {pattern}", file=f)

  advanced_ips = [ip for ip, d in classified_output.items() if d['skill'].startswith('script')]
  for ip in advanced_ips[:38]:  # spot check 5
    sessions = ip_commands[ip]['sessions']
    for sid, cmds in list(sessions.items())[:1]:
      print(f"\n{ip} session {sid}:")
      for ts, cmd in cmds[:10]:
        print(f"{cmd}")