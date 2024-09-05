from argparse import ArgumentParser
import os
parser = ArgumentParser()
parser.add_argument('--private-key-name',default="",type=str,help="private ssh key for authority")
args = parser.parse_args()
ssh_config_path = os.path.expanduser('~/.ssh/config')
ssh_config_content = f"""
    Host github.com
        HostName ssh.github.com
        User git
        Port 443
        StrictHostKeyChecking no
        IdentityFile ~/.ssh/{args.private_key_name}
    """
with open(ssh_config_path, 'w') as f:
    f.write(ssh_config_content)