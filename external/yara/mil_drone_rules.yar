/*
    HackersEra Unified Threat Detection Rules
    Applicable for: Automotive, Drones, Embedded, IoT, Defense Firmware
*/

rule GNSS_Leak
{
    meta:
        author = "HackersEra"
        description = "Hardcoded GNSS NMEA telemetry strings"
        severity = "medium"
        category = "telemetry"
        tags = "GNSS"
        reference = "https://hackersera.com"

    strings:
        $gps     = "$GPGGA"
        $glonass = "$GLGSV"
        $beidou  = "$BDGSV"
        $galileo = "$GAGSV"
        $coord1  = "3111.345,N,12122.345,E"
        $coord2  = "4250.5589,N,08335.7456,W"

    condition:
        any of them
}

rule SATCOM_Protocol_Leak
{
    meta:
        author = "HackersEra"
        description = "Hardcoded SATCOM packet keywords"
        severity = "medium"
        category = "telemetry"
        tags = "SATCOM"
        reference = "https://hackersera.com"

    strings:
        $cmd1 = "$SATCMD,PING,ACK"
        $cmd2 = "$SAT,PKT,0x"
        $lib1 = "Iridium9602"
        $lib2 = "Inmarsat-BGAN"

    condition:
        any of them
}

rule CAN_Spoofing
{
    meta:
        author = "HackersEra"
        description = "Suspicious CAN ID override or crash trigger"
        severity = "critical"
        category = "can_attack"
        tags = "CAN"
        reference = "https://hackersera.com"

    strings:
        $id      = "0x133"
        $trigger = "EMERGENCY OVERRIDE"
        $payload = "ACTUATE_FLAPS"

    condition:
        all of them
}

rule Remote_Access_Backdoor
{
    meta:
        author = "HackersEra"
        description = "Netcat shell, hidden init script, or bind shell"
        severity = "high"
        category = "persistence"
        tags = "Backdoor,Init"
        reference = "https://hackersera.com"

    strings:
        $nc1  = "nc -l -p 4444 -e /bin/sh"
        $nc2  = "nc -lvp 1337 -e /bin/sh"
        $init = "/etc/init.d/.remote_init"

    condition:
        any of them
}

rule Hardcoded_Credentials
{
    meta:
        author = "HackersEra"
        description = "Detect hardcoded backdoor user/pass"
        severity = "high"
        category = "access_control"
        tags = "Backdoor,Credentials"
        reference = "https://hackersera.com"

    strings:
        $user1 = "fieldop"
        $pass1 = "milops#2025"
        $pass2 = "admin123"
        $pass3 = "falcon9"

    condition:
        2 of them
}

rule Unsafe_Code_Functions
{
    meta:
        author = "HackersEra"
        description = "Use of unsafe C standard library functions"
        severity = "medium"
        category = "code_quality"
        tags = "CWE,UnsafeFunction"
        reference = "https://hackersera.com"

    strings:
        $gets    = "gets("
        $strcpy  = "strcpy("
        $memcpy  = "memcpy("
        $system  = "system("

    condition:
        any of them
}

rule Firmware_Crash_Trigger
{
    meta:
        author = "HackersEra"
        description = "Firmware kill-switch or DoS trigger via system()"
        severity = "critical"
        category = "dos_trigger"
        tags = "Crash,DoS"
        reference = "https://hackersera.com"

    strings:
        $reboot = "reboot -f"
        $abort  = "CMD:ABORT"

    condition:
        any of them
}

rule Embedded_SBOM_Tag
{
    meta:
        author = "HackersEra"
        description = "Embedded SBOM version strings for FlightParser / CANStack"
        severity = "low"
        category = "sbom_leak"
        tags = "SBOM"
        reference = "https://hackersera.com"

    strings:
        $fp = "FlightParser v1.1"
        $cs = "CANStack v2.3.7"
        $rs = "RemoteShell netcat"

    condition:
        any of them
}
