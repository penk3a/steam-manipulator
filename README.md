# PoC of Steam session token dumping and login
> [!CAUTION]
> This tool is provided for **educational and research purposes only**. Intended for security researchers, pentesters, and those studying Windows DPAPI and Steam authentication internals. Use only on accounts you own or have explicit authorization to test. Unauthorized access to computer accounts is illegal. The author assumes no responsibility for misuse.
## How it works
Steam caches JWT tokens in %LOCALAPPDATA%\steam\local.vdf

Encrypted via CryptProtectData with login as entropy.

Token format - login.eyAidHlwIjogIkpXVCIs...header.payload.signature
## Requirements
```
pip install pywin32 vdf PyJWT
```
## Usage
```
# Dump all active sessions
python dump.py
```
```
# Login to stolen token
python login.py
```
## Files
local.vdf	(%LOCALAPPDATA%\steam\) - Encrypted token storage

loginusers.vdf (Steam\config\) - Account registry

config.vdf (Steam\config\) - Account-SteamID mapping

localconfig.vdf (Steam\userdata\<id>\config\) - User preferences
