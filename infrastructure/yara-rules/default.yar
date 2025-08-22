/*
    VirusJaeger Default Yara Rules
    
    These rules provide basic malware detection capabilities.
    Add your own custom rules to extend detection.
*/

rule EICAR_Test_File {
    meta:
        description = "EICAR Anti-Virus Test File"
        author = "VirusJaeger"
        severity = "high"
        
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $eicar_alt = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        
    condition:
        any of them
}

rule PE_File {
    meta:
        description = "Portable Executable File"
        author = "VirusJaeger"
        severity = "info"
        
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Suspicious_Strings {
    meta:
        description = "Contains suspicious strings often found in malware"
        author = "VirusJaeger"
        severity = "medium"
        
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase
        $cmd3 = "rundll32.exe" nocase
        $cmd4 = "regsvr32.exe" nocase
        
        $api1 = "CreateRemoteThread" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "SetWindowsHookEx" nocase
        
        $reg1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        
    condition:
        2 of them
}

rule Base64_Encoded_PE {
    meta:
        description = "Base64 encoded PE file"
        author = "VirusJaeger"
        severity = "high"
        
    strings:
        $b64_pe = /TVqQ[A-Za-z0-9+\/]{20,}/
        
    condition:
        $b64_pe
}

rule Packed_Executable {
    meta:
        description = "Potentially packed executable"
        author = "VirusJaeger"
        severity = "medium"
        
    strings:
        $upx = "UPX!"
        $aspack = "aPSPack"
        $fsg = "FSG!"
        $petite = "petite"
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Network_Activity {
    meta:
        description = "Contains network-related strings"
        author = "VirusJaeger"
        severity = "medium"
        
    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $url3 = "ftp://" nocase
        
        $net1 = "URLDownloadToFile" nocase
        $net2 = "InternetOpenUrl" nocase
        $net3 = "WSAStartup" nocase
        $net4 = "socket" nocase
        $net5 = "connect" nocase
        
    condition:
        any of ($url*) and any of ($net*)
}

rule Crypto_References {
    meta:
        description = "Contains cryptographic function references"
        author = "VirusJaeger"
        severity = "low"
        
    strings:
        $crypt1 = "CryptAcquireContext" nocase
        $crypt2 = "CryptCreateHash" nocase
        $crypt3 = "CryptEncrypt" nocase
        $crypt4 = "CryptDecrypt" nocase
        
        $hash1 = "MD5" nocase
        $hash2 = "SHA1" nocase
        $hash3 = "SHA256" nocase
        
    condition:
        any of them
}