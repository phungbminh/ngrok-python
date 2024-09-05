import os
import subprocess
from argparse import ArgumentParser

current_path = os.path.abspath(globals().get("__file__","."))
current_dir = os.path.dirname(current_path)

root_dir = os.path.abspath(f"{current_dir}/../../../")

parser = ArgumentParser()
parser.add_argument('--giturl',default="",type=str,help="giturl to clone")
parser.add_argument('--folder',default="",type=str,help="folder clone to")
parser.add_argument('--branch',default="DEV",type=str,help="branch to clone")
parser.add_argument('--private-key-path',default="",type=str,help="private ssh key for authority")

args = parser.parse_args()
name_key = args.private_key_path.split("/")[-1]

def init_project(scope=globals(), cfg={}, **kwargs):
    import os
    #if not os.path.exists(f'{root_dir}/resyslab_utils'):
     #   print("\033[1;31m---------------you could have cloned resyslab_utils first!---------------\033[0m")
      #  return
    # init prj_rsa
    rsa_dir = os.path.expanduser('~/.ssh/')
    os.makedirs(rsa_dir, exist_ok=True)
    subprocess.run(["cp", args.private_key_path, os.path.join(rsa_dir, name_key)], check=True)
    subprocess.run(["chmod", "600", os.path.join(rsa_dir, name_key)], check=True)

    # Configuring SSH for GitHub
    ssh_config = f"""
    Host github.com
        HostName ssh.github.com
        User git
        Port 443
        StrictHostKeyChecking no
        IdentityFile ~/.ssh/{name_key}
    """
    with open(os.path.join(rsa_dir, "config"), "w") as f:
        f.write(ssh_config)

    if not os.path.exists(args.folder):
        subprocess.run(["git", "clone", args.giturl, args.folder], check=True)
    else:
        subprocess.run(["git", "pull"], cwd=args.folder, check=True)
    subprocess.run(["git", "checkout", args.branch], cwd=args.folder, check=True)

    if scope is not None:
        scope.update(locals())

    # Call cloud_setup functions if needed
    # Example: cloud_setup.start_ssh(...)

    # Add any additional logic here

# Example usage:
init_project()
