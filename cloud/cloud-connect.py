def start_ssh(id_rsa_pub="", password="", install_ssh=False, config_ssh=False):
    """
    Start SSH as follows:
    + Add id_rsa.pub into ~/.ssh/authorized_keys
    + Install SSH service with Port 22 and password
    + Set command prompt
    """
    from IPython import get_ipython
    import os
    print(f'{"*" * 10} SETUP SSH SERVICE {"*" * 10}')

    if install_ssh is True:
        get_ipython().system('sudo apt-get update -y')
        get_ipython().system('conda install openssh -y')
        get_ipython().system('echo "> Install ssh service..."')
        get_ipython().system('apt-get install ssh -y 2>&1 > /dev/null')
        get_ipython().system('sudo dpkg --configure -a')
        
    if id_rsa_pub != "":
        get_ipython().system('echo "> Copy public key to authorized keys..."')
        get_ipython().system('mkdir -p ~/.ssh')
        get_ipython().system(f'echo {id_rsa_pub} > ~/.ssh/authorized_keys')

    if config_ssh is True:
        get_ipython().system('echo "> Config ssh service..."')
        get_ipython().system("sed -i 's/^#Port.*/Port 22/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^UsePrivilegeSeparation .*/UsePrivilegeSeparation no/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#Port.*/Port 22/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#ListenAddress 0.*/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#ListenAddress ::.*/ListenAddress ::/' /etc/ssh/sshd_config")

        get_ipython().system("sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config")

        get_ipython().system("sed -i 's/^#AllowAgentForwarding.*/AllowAgentForwarding yes/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#PermitTTY.*/PermitTTY yes/' /etc/ssh/sshd_config")
        get_ipython().system("sed -i 's/^#GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config")
        # !systemctl reload sshd

    if password != "":
        get_ipython().system('echo "> Set root password..."')
        get_ipython().system(f'echo -e "$password\n{password}" | passwd root >/dev/null 2>&1')

    get_ipython().system('echo "> Restart SSH service..."')
    get_ipython().system('service ssh restart')
    print(f"")

    get_ipython().system('echo "> Process ~/.bashrc to registry PS1, TERM..."')
    get_ipython().system('grep -qx "^PS1=.*$" ~/.bashrc || echo "PS1=" >> ~/.bashrc')
    dest = "PS1='\\[\\e]0;\\u@\h: \\w\\a\\]${debian_chroot:+($debian_chroot)}\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\$ '"
    cmd = "sed -i \"s/$(echo $src | sed -e 's/\\([[\\/.*]\\|\\]\\)/\\\\&/g').*/$(echo $dest | sed -e 's/[\\/&]/\\\\&/g')/g\" ~/.bashrc"
    get_ipython().system(f'src="PS1=" && echo $src && dest="{dest}" && echo "$dest" && {cmd}')

    cmd = 'grep -qx "^TERM=.*$" ~/.bashrc || echo "TERM=xterm-256color" >> ~/.bashrc'
    get_ipython().system(f'{cmd}')
    print(f"")

    print(f'{"-" * 10} Finished {"-" * 10}\n')
    pass  # start_ssh


def start_ngrok(ngrok_tokens=[], ngrok_binds={}):
    """
    Initialize ngrok tunnels based on provided tokens and port bindings.

    :param ngrok_tokens: List of ngrok authentication tokens.
    :param ngrok_binds: Dictionary of services to expose with their respective port and protocol.
                        Example: {'ssh': {'port': 22, 'type': 'tcp'}, 'vscode': {'port': 9000, 'type': 'http'}}
    """

    def default_handler(ngrok, ngrok_info):
        for name, settings in ngrok_binds.items():
            try:
                tunnel = ngrok.connect(settings.get('port', 80), settings.get('type', 'tcp'))
                ngrok_info[name] = tunnel.public_url
            except Exception as e:
                print(f"Error establishing {name}: {e}")
                raise

    print(f'{"*" * 10} SETUP NGROK {"*" * 10}')
    try:
        from pyngrok import ngrok, conf
    except:
        # install pyngrok
        print(f'> Install ngrok...')
        get_ipython().system('pip install -qqq pyngrok 2>&1 > /dev/null')
        from pyngrok import ngrok, conf

    # Kill existing ngrok processes
    print('> Kill ngrok process...')
    get_ipython().system('kill -9 "$(pgrep ngrok)"')

    print('> Binding ports...')
    list_regions = ["us", "eu", "au", "jp"]
    ngrok_info = {}
    is_success = False

    for auth_token in ngrok_tokens:
        if is_success:
            break
        for region in list_regions:
            try:
                conf.get_default().region = region
                ngrok.set_auth_token(auth_token)
                default_handler(ngrok, ngrok_info)
                print("> Registry success!")
                is_success = True
                break
            except Exception as e:
                print(f"Failed in region {region} with token {auth_token}: {e}")

    for key in ngrok_info:
        print(f'{key}: {ngrok_info[key]}')

    print(f"")

    print(f'{"-" * 10} Finished {"-" * 10}\n')
    return ngrok_info
    pass


def base64_encode(s):
    import os
    result = os.popen(f'echo "{s}" | base64 -w 0').read().strip()
    return result
    pass  # base64_encode


def base64_decode(s):
    import base64
    return base64.b64decode(s).decode('ascii')
    pass  # base64_decode


def connect_ngrok(scope=globals(), cfg={}, **kwargs):
    # kaggle config
    import base64
    from kaggle_secrets import UserSecretsClient
    user_secrets = UserSecretsClient()
    kaggle_cfg = {}
    for name in ['NGROK_TOKEN_1', 'ID_RSA_PUB', 'SSH_PASS']:
        try:
            kaggle_cfg[name] = user_secrets.get_secret(name)
        except:
            pass
    kaggle_cfg.update(**cfg)

    ngrok_token_val = kaggle_cfg.get("NGROK_TOKEN_1", "")
    id_rsa_pub = kaggle_cfg.get("ID_RSA_PUB", "1")
    ssh_pass_val = kaggle_cfg.get("SSH_PASS", "12345")

    # ssh 
    start_ssh(id_rsa_pub=id_rsa_pub,
              install_ssh=True,
              config_ssh=True,
              password=ssh_pass_val)
    ngrok_binds = kwargs.get('ngrok_binds', {})
    # open port ssh to publi
    ngrok_info = start_ngrok([ngrok_token_val], ngrok_binds)
    return ngrok_info

def setup_config_github(id_rsa_val, id_rsa_name, hostname="github.com", append = False, show_id_rsa = False):
    print(f'{"*" * 10} CONFIG GITHUB {"*"*10}')
    
    print('> Add id_rsa...')
    get_ipython().system('mkdir -p ~/.ssh')
    get_ipython().system(f'echo "{id_rsa_val}" > ~/.ssh/{id_rsa_name}')
    get_ipython().system(f'chmod 600 ~/.ssh/{id_rsa_name}')

    ssh_config  = f"Host {hostname}\n"
    ssh_config +=  "    HostName ssh.github.com\n"
    ssh_config +=  "    User git\n"
    ssh_config +=  "    Port 443\n"
    ssh_config +=  "    StrictHostKeyChecking no\n"
    ssh_config += f"    IdentityFile ~/.ssh/{id_rsa_name}"

    if append is False:
        print('> Add config file...')
        get_ipython().system('echo "$ssh_config" > ~/.ssh/config')
    else:
        print('> Append config file...')
        get_ipython().system('echo "$ssh_config" >> ~/.ssh/config')

    print('> List ~/.ssh...')
    get_ipython().system('ls ~/.ssh')
    
    if show_id_rsa:
        print('> Show id_rsa...')
        get_ipython().system(f'cat ~/.ssh/{id_rsa_name}')
    
    print('> Show config...')
    get_ipython().system(f'cat ~/.ssh/config')
    
    print('> Test ssh...')
    get_ipython().system(f'ssh {hostname}')
    pass # setup_config_github
