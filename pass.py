import subprocess
import platform
import re
import os
from datetime import datetime

def get_windows_wifi_passwords():
    """Retrieve saved Wi-Fi passwords on Windows"""
    profiles_data = subprocess.check_output("netsh wlan show profiles", shell=True, text=True, errors="ignore")
    profiles = re.findall(r"All User Profile\s*:\s*(.*)", profiles_data)

    wifi_list = []
    for profile in profiles:
        try:
            profile_info = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True, text=True, errors="ignore")
            password_match = re.search(r"Key Content\s*:\s*(.*)", profile_info)
            security_match = re.search(r"Authentication\s*:\s*(.*)", profile_info)
            password = password_match.group(1) if password_match else "N/A"
            security = security_match.group(1) if security_match else "Unknown"
            wifi_list.append({"SSID": profile, "Password": password, "Security": security})
        except subprocess.CalledProcessError:
            pass
    return wifi_list


def get_linux_wifi_passwords():
    """Retrieve saved Wi-Fi passwords on Linux (NetworkManager)"""
    wifi_list = []
    path = "/etc/NetworkManager/system-connections/"
    if not os.path.exists(path):
        return wifi_list

    for filename in os.listdir(path):
        try:
            full_path = os.path.join(path, filename)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            ssid_match = re.search(r"^ssid=(.*)", content, re.MULTILINE)
            psk_match = re.search(r"^psk=(.*)", content, re.MULTILINE)
            key_mgmt_match = re.search(r"^key-mgmt=(.*)", content, re.MULTILINE)
            ssid = ssid_match.group(1) if ssid_match else filename
            password = psk_match.group(1) if psk_match else "N/A"
            security = key_mgmt_match.group(1) if key_mgmt_match else "Unknown"
            wifi_list.append({"SSID": ssid, "Password": password, "Security": security})
        except Exception:
            pass
    return wifi_list


def get_macos_wifi_passwords():
    """Retrieve saved Wi-Fi passwords on macOS"""
    wifi_list = []
    try:
        network_services = subprocess.check_output(
            "networksetup -listpreferredwirelessnetworks en0", shell=True, text=True, errors="ignore"
        )
        ssids = re.findall(r"\s+(.*)", network_services)
        for ssid in ssids:
            try:
                password = subprocess.check_output(
                    f"security find-generic-password -D 'AirPort network password' -a '{ssid}' -w",
                    shell=True, text=True, errors="ignore"
                ).strip()
            except subprocess.CalledProcessError:
                password = "N/A"
            wifi_list.append({"SSID": ssid, "Password": password, "Security": "Unknown"})
    except Exception:
        pass
    return wifi_list


def display_results(results):
    print("\n{:<30} {:<20} {:<15}".format("SSID", "Password", "Security"))
    print("-" * 70)
    for wifi in results:
        print("{:<30} {:<20} {:<15}".format(wifi["SSID"], wifi["Password"], wifi["Security"]))


if __name__ == "__main__":
    system = platform.system()
    if system == "Windows":
        results = get_windows_wifi_passwords()
    elif system == "Linux":
        results = get_linux_wifi_passwords()
    elif system == "Darwin":
        results = get_macos_wifi_passwords()
    else:
        print("Unsupported OS")
        results = []

    if results:
        display_results(results)
    else:
        print("No saved Wi-Fi networks found or insufficient permissions.\nRun with elevated privileges if needed.")
