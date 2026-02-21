import os
import time
import pathlib
import subprocess
import binascii
import zlib
import vdf
import jwt
import win32crypt

def login():
    print("\n=== Steam Token Login ===\n")

    token_input = input("Enter token: ").strip()
    token_input = ''.join(c for c in token_input if c.isascii() and c.isprintable())

    if token_input.count('.') != 3:
        print("[-] Invalid token format")
        return

    login = token_input[:token_input.find('.')]
    token = token_input[token_input.find('.') + 1:]

    print(f"[*] Login: {login}")

    try:
        payload = jwt.decode(token, options={'verify_signature': False})
        steamid = payload['sub']
        print(f"[+] SteamID: {steamid}")
    except Exception as e:
        print(f"[-] Failed to decode token: {e}")
        return

    steam_paths = [
        'C:\\Program Files (x86)\\Steam',
        'C:\\Program Files\\Steam',
    ]

    steamdir = None
    for p in steam_paths:
        if os.path.exists(os.path.join(p, 'steam.exe')):
            steamdir = p
            break

    if not steamdir:
        steamdir = input("Steam not found. Enter path: ").strip()

    if not steamdir.endswith('\\'):
        steamdir += '\\'

    print(f"[+] Steam: {steamdir}")

    print("[*] Killing Steam...")
    procs = ['Steam.exe', 'steamwebhelper.exe', 'steamservice.exe']
    for proc in procs:
        subprocess.run(f'taskkill /f /im {proc}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Steam32 ID
    steam32 = int(steamid) - 76561197960265728

    udir = f'{steamdir}userdata\\{steam32}\\config'
    pathlib.Path(udir).mkdir(parents=True, exist_ok=True)

    localconfig = {
        "UserLocalConfigStore": {
            "streaming_v2": {"EnableStreaming": "0"},
            "friends": {"SignIntoFriends": "0"}
        }
    }
    try:
        with open(f'{udir}\\localconfig.vdf', 'w', encoding='utf8', errors='ignore') as f:
            vdf.dump(localconfig, f, pretty=True)
        print("[+] localconfig.vdf")
    except Exception as e:
        print(f"[-] localconfig.vdf failed: {e}")

    pathlib.Path(f'{steamdir}config').mkdir(parents=True, exist_ok=True)
    config_file = f'{steamdir}config\\config.vdf'

    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf8', errors='ignore') as f:
                config = vdf.load(f)
            if "InstallConfigStore" in config and "Software" in config["InstallConfigStore"] and \
               "Valve" in config["InstallConfigStore"]["Software"] and \
               "Steam" in config["InstallConfigStore"]["Software"]["Valve"]:
                if "Accounts" not in config["InstallConfigStore"]["Software"]["Valve"]["Steam"]:
                    config["InstallConfigStore"]["Software"]["Valve"]["Steam"]["Accounts"] = {}
                config["InstallConfigStore"]["Software"]["Valve"]["Steam"]["Accounts"][login] = {"SteamID": steamid}
            else:
                raise Exception("bad structure")
        except:
            config = {"InstallConfigStore": {"Software": {"Valve": {"Steam": {"Accounts": {login: {"SteamID": steamid}}}}}}}
    else:
        config = {"InstallConfigStore": {"Software": {"Valve": {"Steam": {"Accounts": {login: {"SteamID": steamid}}}}}}}

    with open(config_file, 'w', encoding='utf8', errors='ignore') as f:
        vdf.dump(config, f, pretty=True)
    print("[+] config.vdf")

    loginusers_file = f'{steamdir}config\\loginusers.vdf'
    user_entry = {
        "AccountName": login,
        "PersonaName": login,
        "RememberPassword": "1",
        "WantsOfflineMode": "0",
        "SkipOfflineModeWarning": "0",
        "AllowAutoLogin": "0",
        "MostRecent": "1",
        "Timestamp": str(round(time.time()))
    }

    if os.path.exists(loginusers_file):
        try:
            with open(loginusers_file, 'r', encoding='utf8', errors='ignore') as f:
                loginusers = vdf.load(f)
            if "users" in loginusers:
                for uid, udata in loginusers['users'].items():
                    udata['MostRecent'] = '0'
                loginusers['users'][steamid] = user_entry
            else:
                loginusers = {"users": {steamid: user_entry}}
        except:
            loginusers = {"users": {steamid: user_entry}}
    else:
        loginusers = {"users": {steamid: user_entry}}

    with open(loginusers_file, 'w', encoding='utf8', errors='ignore') as f:
        vdf.dump(loginusers, f, pretty=True)
    print("[+] loginusers.vdf")

    localst = os.getenv('LOCALAPPDATA') + '\\steam'
    pathlib.Path(localst).mkdir(parents=True, exist_ok=True)

    pwdHash = win32crypt.CryptProtectData(token.encode(), None, login.encode(), None, None, 0)
    pw = str(binascii.hexlify(pwdHash), encoding='ascii')
    hdr = hex(zlib.crc32(login.encode()) & 4294967295).replace('0x', '') + '1'

    local_file = f'{localst}\\local.vdf'
    if os.path.exists(local_file):
        try:
            with open(local_file, 'r', encoding='utf8', errors='ignore') as f:
                existing_local = vdf.load(f)
            if "MachineUserConfigStore" in existing_local and "Software" in existing_local["MachineUserConfigStore"] and \
               "Valve" in existing_local["MachineUserConfigStore"]["Software"] and \
               "Steam" in existing_local["MachineUserConfigStore"]["Software"]["Valve"] and \
               "ConnectCache" in existing_local["MachineUserConfigStore"]["Software"]["Valve"]["Steam"]:
                existing_local["MachineUserConfigStore"]["Software"]["Valve"]["Steam"]["ConnectCache"][hdr] = pw
            else:
                existing_local = {"MachineUserConfigStore": {"Software": {"Valve": {"Steam": {"ConnectCache": {hdr: pw}}}}}}
            with open(local_file, 'w', encoding='utf8', errors='ignore') as f:
                vdf.dump(existing_local, f, pretty=True)
        except:
            with open(local_file, 'w', encoding='utf8', errors='ignore') as f:
                vdf.dump({"MachineUserConfigStore": {"Software": {"Valve": {"Steam": {"ConnectCache": {hdr: pw}}}}}}, f, pretty=True)
    else:
        with open(local_file, 'w', encoding='utf8', errors='ignore') as f:
            vdf.dump({"MachineUserConfigStore": {"Software": {"Valve": {"Steam": {"ConnectCache": {hdr: pw}}}}}}, f, pretty=True)
    print("[+] local.vdf (DPAPI encrypted)")

    print(f"\n[*] Launching Steam as '{login}'...")
    os.system('start steam://0')
    print("[+] Done!")

    input("\nPress Enter to exit...")


if __name__ == '__main__':
    login()