Windows Integrity Levels & Process Relationships: Defender/Attacker Implications

Script: 02_ArcanumI_week2_process_scry.py

Integrity Level Mechanism:

    Windows uses Mandatory Integrity Control (MIC) to enforce security boundaries

    Processes inherit integrity levels from parents unless explicitly modified

    Higher integrity processes can modify lower ones, but not vice-versa

Defender Significance:

    Privilege Escalation Detection: Unexpected high-integrity child processes indicate potential exploitation

    Sandbox Containment: Low-integrity processes should not spawn high-integrity children

    Service Hardening: Critical services should run at appropriate levels (not SYSTEM unless necessary)

    UAC Monitoring: Integrity level changes may indicate UAC bypass attempts

Attacker Exploitation Patterns:

    Parent-Child Manipulation: Injecting into high-integrity parents to gain elevated privileges

    Token Impersonation: Stealing tokens from higher-integrity processes

    Shatter Attacks: Lower-integrity processes sending messages to higher-integrity UI elements

    Process Hollowing: Replacing child process memory while maintaining parent's integrity level

Defensive Monitoring Strategies:

    Monitor process creation events with integrity level discrepancies

    Alert on medium/low integrity processes spawning high-integrity children

    Track integrity level changes during process lifetime

    Correlate with other indicators like network connections and file modifications
