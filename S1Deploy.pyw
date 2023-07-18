import PySimpleGUI as sg
from os import path
import subprocess
import threading
import os.path
import shutil
import ping3
import sys
import wmi
import csv
import re
import io

version = 1.0

def ping_machine(ip_address):
    try:
        output = subprocess.check_output(["ping", "-n", "1", ip_address])
        output_text = output.decode("utf-8")
        if "Reply from {}:".format(ip_address) in output_text:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

# Function for getting WMI info from endpoint
def get_computer_info(ip_address, user, password):
    try:
        # Pull what we want from remote computer using WMI
        s1_agent_present = wmi.WMI(ip_address, user=user, password = password).Win32_Product(Name="Sentinel Agent")

        for os in wmi.WMI(ip_address, user=user, password = password).win32_OperatingSystem():
            os_version = os.Version
            os_build_number = os.BuildNumber
            os_architecture = os.OSArchitecture
            os_name = os.Caption
        
        for cs in wmi.WMI(ip_address, user=user, password = password).Win32_ComputerSystem():
            computer_name = cs.Name
            dns_hostname = cs.DNSHostName
            domain_role_int = cs.DomainRole
        
        # If S1 isn't installed the return from WMI will be null
        if s1_agent_present == []:
            s1_agent = False
        else:
            s1_agent = True

        # Getting domain role info and putting into table
        domain_roles = {
        0: "Standalone Workstation",
        1: "Member Workstation",
        2: "Standalone Server",
        3: "Member Server",
        4: "Backup Domain Controller",
        5: "Primary Domain Controller",
        }

        if domain_role_int in domain_roles:
            domain_role = domain_roles[domain_role_int]
        else:
            domain_role = "Unknown"

        return {
            "computer_name": computer_name,
            "dns_hostname": dns_hostname,
            "IP_Address" : f'{ip_address}',
            "s1_agent": s1_agent,
            "domain_role": domain_role,
            "os_version": os_version,
            "os_build_number": os_build_number,
            "os_architecture": os_architecture,
            "os_name": os_name,
        }
    except Exception as e:
        print(f"Unable to connect to {ip_address} using WMI \nThis endpoint could be a different OS than windows or the firewall is enabled, check the exception below...")
        print(e)
        computer_info = False
        return computer_info

# Export report function
def export_to_csv(data, file_name):
  
    # no data, no export 
    if not data:
        return

  # making folder on the desktop and then exporting files to it 
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    s1dep_logs_path = os.path.join(desktop_path, "s1dep_logs")
    if not os.path.exists(s1dep_logs_path):
        os.mkdir(s1dep_logs_path)
    
    file_path = os.path.join(s1dep_logs_path, file_name)

    with open(file_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Write header row
        writer.writerow(data[0].keys())
        # Write data rows
        for item in data:
            writer.writerow(item.values())
    csv_file.close()

class SGMultiLineWrapper(io.StringIO):
    def __init__(self, multiline_element):
        super().__init__()
        self.multiline_element = multiline_element

    def write(self, text):
        self.multiline_element.update(value=self.getvalue() + text)

def work_work_zug_zug(window, values):

    # Setting up all necessary variables based on the users input
    msi_filepath = values["in1"]
    site_token = values["in2"]
    ip_octet = values["in3"]
    starting_ip_str = values["in4"]
    starting_ip = int(starting_ip_str)
    ending_ip_str = values["in5"]
    ending_ip = int(ending_ip_str)
    ip_range = list(range(starting_ip, ending_ip))
    num_ips = len(ip_range)
    temp_drive_letter = values["in6"]
    temp_drive = f"{temp_drive_letter}:\\"
    username = values["in7"]
    password = values["in8"]

    # Have to break up the filepath to MSI for the argument list
    path_parts = os.path.split(msi_filepath)
    msi_agent = path_parts[-1]
    destination_file_path = temp_drive + msi_agent
    program_path = rf'C:\{msi_agent}'



    # Clear error messages and set the error action preference
    sys.stderr.write("")
    sys.tracebacklimit = 0

    missing_S1 = []
    unavailable = []
    have_S1 = []
    WMI_fail = []

    # Start looping through the IP's
    window['-OUTPUT-'].update('')
    print('\n')
    print("Starting the IP evaluation and S1 installations...")
    for ip in ip_range:
        ip_address = ip_octet + str(ip)
        print('\n')
        print(f"Evaluating {ip_address}")

        # Test connection to IP
        is_ping_successful = ping_machine(ip_address)
        

        # If the return ouput is '0', the connection state was successful and we continue to attempt to connect to WMI next
        if is_ping_successful == True:
            # Attempt WMI connection
            print("Machine is alive...attempting to connect to WMI service and check S1 installation status")
            computer_info = get_computer_info(ip_address, username, password)
            # If the return from the function returns false bool, WMI connection failed, if computer_info = anything else, it worked
            if computer_info != False:
                print("WMI connection successful! hostname for the system is " + computer_info["dns_hostname"])

                # Check to see if S1 agent is installed.
                if computer_info["s1_agent"] == False:
                    print("S1 agent is not installed...attempting to copy over installation files")

                    # Attempt to copy over files
                    # figure out creds situation here..... 
                    net_use_command = f'net use {temp_drive_letter}: \\\\{ip_address}\\C$ {password} /user:{username}'
                    subprocess.run(net_use_command, shell=True)
                    
                    # Copy the file to the target
                    shutil.copyfile(msi_filepath, destination_file_path)
                    
                    print("Copy complete")

                    # WMI connection
                    c = wmi.WMI(computer=ip_address, user=username, password=password)

                    # Construct the installation command
                    # command = f'msiexec /i "{program_path}" SITE_TOKEN={site_token}'

                        # Force restart yes/no
                    if values["in9"] == True:
                        argument_list = f'msiexec /i "{program_path}" SITE_TOKEN={site_token}'
                    else:
                        argument_list = f'msiexec /i "{program_path}" /QUIET /NORESTART SITE_TOKEN={site_token}'

                    process_id, result = c.Win32_Process.Create(CommandLine=argument_list)

                    # Check if the process was successfully created
                    if result == 0:
                        print(f'Installation process started with Process ID: {process_id}')
                        print("Instantiating install...")

                        install = False
                        stop = False
                        counter = 0

                        #instantiate install
                        process_watcher = c.Win32_Process.watch_for("creation")
                        while stop == False:
                            new_process = process_watcher()
                            if new_process.Caption == "SentinelCtl.exe":
                                stop = True
                                install = True

                            elif counter == 80:
                                stop = True
                            else:
                                counter += 1

                        if install == True:
                            print("SentinelOne install successfully instantiated!")
                        else:
                            print("SentinelOne install cannot be instatiated: This could be because the installer itself failed, or the machine is old, slow and dusty..meaning the installer hasn't finshed")
                    else:
                        print(f'Installation command failed to execute.')

                    # Disconnect the temporary drive
                    net_use_delete_command = f'net use {temp_drive_letter}: /delete'
                    subprocess.run(net_use_delete_command, shell=True)

                    # Append the computer_info data retreived from WMI to the list for later export
                    missing_S1.append(computer_info)
                else:
                    print("S1 agent is already installed, moving on...")

                    # Append the computer_info data retreived from WMI to the list for later export
                    have_S1.append(computer_info)
            else:
                print(f"Recording endpoint in logs and moving on...")

                # Attempt to get dns data on the host that did not respond to WMI and append to list for later export
                result = subprocess.run(["nslookup", "-type=PTR", ip_address], capture_output=True, text=True)
                pattern = r"name = (.+)$"
                matches = re.search(pattern, result.stdout, re.MULTILINE)
                if matches:
                    hostname = matches.group(1).strip()
                    WMI_fail.append({
                        "IPAddress": ip_address,
                        "ComputerName": hostname
                    })
                else:
                    WMI_fail.append({"IPAddress": ip_address})
        else:
            print(f"{ip_address} is not alive")
            unavailable.append({"IPAddress": ip_address})

    # Report in terminal
    print("\n")
    print("ALL IP'S COMPLETE - STATISTICS BELOW:")
    print("Total IP Addresses evaluated    :", num_ips)
    print("Hosts that were missing S1      :", len(missing_S1))
    print("Hosts that have S1              :", len(have_S1))
    print("Alive but not responding to WMI :", len(WMI_fail))
    print("Not responding to ping          :", len(unavailable))

    # Export logs to the desktop
    export_to_csv(missing_S1, 'Hosts_MissingS1.csv')
    export_to_csv(have_S1, 'Hosts_WithS1.csv')
    export_to_csv(unavailable, 'Hosts_Unavailable.csv')
    export_to_csv(WMI_fail, 'WMI_Fail.csv')

    print("Exported log files are located on the desktop")

def main():
    sg.theme('Darkteal6')

    layout = [
        [sg.T("")],
        [sg.Text("     Select the SentinelOne .MSI installer")],
        [sg.Text("", size=(1, 1)), sg.Input(size=80), sg.FilesBrowse(key="in1")],
        [sg.Text("     Paste in the site token below")],
        [sg.Text("", size=(1, 1)), sg.Input(size=110, key="in2")],
        [sg.Text("     Define the network to run the installer on")],
        [sg.Text("     As an example, to run the installer on IP addresses between 192.168.68.2 - 192.168.68.254, use the following:")],
        [sg.Text("     IP Octet: 192.168.68."), sg.Text("     IP Octet:"), sg.Input(size=15, key="in3")],
        [sg.Text("     Starting IP: 2"), sg.Text("             Starting IP:"), sg.Input(size=5, key="in4")],
        [sg.Text("     Ending IP: 255"), sg.Text("            Ending IP:"), sg.Input(size=5, key="in5")],
        [sg.Text("     Enter an unused network drive path that will be used to temporarily mount the agent, default would be 'Y' (do not include ':')"), sg.Input(size=5, key="in6")],
        [sg.Text("     Enter the domain username, Ex: 'test.local\\administrator'"), sg.InputText(key='in7')],
        [sg.Text("     Enter the password, this will not be passed in plain-text  "), sg.InputText(key='in8', password_char='*')],
        [sg.T(""), sg.Checkbox("Force restart? This will be happen within 45 seconds of the installation file being transferred", default=False, key="in9")],
        [sg.Text("     Change the parameters as necessary and click run after each instance completes to deploy to multiple subnets")],
        [sg.Text("     Note: This will overwrite the output logs each time the program finishes all the IP's")],
        [sg.T("")],
        [sg.T("  "), sg.Button('Run', bind_return_key=True), sg.Button('Exit')],
        [sg.T("")],
        [sg.T(""), sg.Multiline(size=(110, 20), reroute_stdout=True, key='-OUTPUT-', disabled=True, autoscroll=True, background_color='#45576c', text_color='white')],
    ]

    window = sg.Window('BinaryLab SentinelOne Deployment', layout, icon=image_path, size=(840, 900))
    stdout_wrapper = SGMultiLineWrapper(window['-OUTPUT-'])

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Exit'):
            window.close()
            sys.stdout = sys.__stdout__
            sys.exit()
            break
        elif event == 'Run':
            threading.Thread(target=work_work_zug_zug, args=(window, values)).start()

if __name__ == '__main__':
    main()

# TC
