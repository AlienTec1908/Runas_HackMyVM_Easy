# Runas - HackMyVM Writeup

![Runas Icon](Runas.png)

## Übersicht

*   **VM:** Runas
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Runas)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 29. Juni 2025
*   **Original-Writeup:** https://alientec1908.github.io/Runas_HackMyVM_Easy/
*   **Autor:** Ben C.

---

**Disclaimer:**

Dieser Writeup dient ausschließlich zu Bildungszwecken und dokumentiert Techniken, die in einer kontrollierten Testumgebung (HackTheBox/HackMyVM) angewendet wurden. Die Anwendung dieser Techniken auf Systeme, für die keine ausdrückliche Genehmigung vorliegt, ist illegal und ethisch nicht vertretbar. Der Autor und der Ersteller dieses README übernehmen keine Verantwortung für jeglichen Missbrauch der hier beschriebenen Informationen.

---

## Zusammenfassung

Die Box "Runas" erforderte eine detaillierte Enumeration sowohl der offenen Ports als auch einer vorhandenen Webanwendung. Nach der Identifizierung offener Ports auf einem Windows 7 System (SMB, RDP, Apache Webserver), wurde eine Local File Inclusion (LFI) Schwachstelle auf der Webseite entdeckt. Diese LFI war durch Pfad-Traversierung und Null-Bytes (`%00`) ausnutzbar und ermöglichte das Auslesen diverser Systemdateien, darunter Logs und Benutzer-Flags.

Durch die Analyse von Windows-Update-Logs, die mittels LFI ausgelesen wurden, konnte ein Passwort-Hash gefunden werden, der dem Benutzer 'runas' zugeordnet war. Das Knacken dieses Hashes lieferte das Passwort für den Benutzer 'runas'. Mit diesen Zugangsdaten war ein Login via RDP möglich.

Als Benutzer 'runas' auf dem System wurde im Windows Credential Manager eine entscheidende Information gefunden: Gespeicherte Anmeldeinformationen für den 'Administrator'. Da diese für die interaktive Anmeldung gespeichert waren, konnte der Benutzer 'runas' den `runas` Befehl nutzen, um Programme mit Administrator-Rechten auszuführen und so die Root-Shell und das Root-Flag zu erlangen.

## Technische Details

*   **Betriebssystem:** Microsoft Windows 7 Professional 7601 Service Pack 1
*   **Offene Ports:**
    *   `80/tcp`: HTTP (Apache httpd 2.4.57 mit PHP/7.2.0)
    *   `135/tcp`: MSRPC
    *   `139/tcp`: NetBIOS SSN
    *   `445/tcp`: Microsoft-DS (SMB)
    *   `3389/tcp`: MS-WBT-Server (RDP)
    *   `5357/tcp`: HTTP (SSDP/UPnP)
    *   Diverse RPC-Ports (49152-49156, 49158)

## Enumeration

1.  **ARP-Scan:** Identifizierung der Ziel-IP (192.168.2.67) im Netzwerk.
2.  **`/etc/hosts` Eintrag:** Hinzufügen von `runas.hmv` zur lokalen hosts-Datei.
3.  **Nmap Scan:** Identifizierung offener Ports und Dienste, Bestätigung eines Windows 7 Systems und offener Dienste wie SMB, RDP und Apache. Nmap identifizierte auch die NetBIOS-Namen WORKGROUP und RUNAS-PC.
4.  **Enum4linux:** Versuche, Benutzer und Shares über SMB zu enumerieren. Zeigte, dass eine anonyme Session möglich ist, aber das Auslesen von Benutzer- und Freigabelisten fehlschlug (NT_STATUS_ACCESS_DENIED).
5.  **Web Enumeration (Port 80):**
    *   `curl`, `nikto`, `gobuster`: Zeigten einen Apache Webserver mit PHP 7.2.0. Directory Indexing war aktiviert. Die Seite `index.php` nahm einen `?file=` Parameter entgegen ("There is no going back!").
    *   LFI-Test (`?file=/etc/passwd`): Zeigte "File not found!".
    *   LFI-Fuzzing mit `wfuzz`: Bestätigung, dass der `file`-Parameter anfällig ist. Fuzzing mit Windows-spezifischen Pfad-Traversierungen (`%5C`, `..//`, `../\..`) und Null-Bytes (`%00`) identifizierte gültige LFI-Payloads.

## Initialer Zugriff (LFI & Informationslecks)

1.  **LFI Ausnutzung:** Die entdeckte LFI-Schwachstelle konnte mittels Pfad-Traversierung und Null-Bytes in Kombination mit dem `file:///` Wrapper ausgenutzt werden, um lokale Dateien zu lesen.
    *   Beispiele: `?file=file:///../../../../../../../../../../../../../../../../../windows/system32/drivers/etc/hosts%00`
2.  **Informationslecks:** Durch das Auslesen von verschiedenen Systemdateien über die LFI wurden kritische Informationen gesammelt:
    *   `/windows/windowsupdate.log`: Enthielt Einträge wie `Attempting to create remote handler process as runas-PC\Administrator in session 1`, was auf einen Benutzer `runas-PC\Administrator` und möglicherweise automatisierte Tasks hindeutete. Es wurde auch ein Hash im Format `; MD5-runas-b3a805b2594befb6c846d718d1224557` gefunden.
    *   `/Users/runas/Desktop/user.txt`: Konnte via LFI ausgelesen werden und enthielt das Benutzer-Flag `HMV{User_Flag_Was_A_Bit_Bitter}`.
    *   `/Users/Administrator/Desktop/root.txt`: Konnte ebenfalls via LFI ausgelesen werden und enthielt einen Hinweis auf das Root-Flag: `HMV{Username_Is_My_Hint}`.
3.  **Passwort-Hash Cracking:** Der im `windowsupdate.log` gefundene MD5-Hash `b3a805b2594befb6c846d718d1224557` wurde mit einem Hash-Cracking-Dienst (`crackstation.net`) oder Tool geknackt und ergab das Passwort `yakuzza`.
4.  **Benutzernamen Identifizierung:** Die im Windows Update Log genannten Benutzer (`runas-PC\Administrator`) sowie die im Login-Screen sichtbaren Benutzernamen (`runas`, `Administrator`) in Kombination mit dem Hinweis im Root-Flag (`Username_Is_My_Hint`) legten nahe, dass `runas` ein relevanter Benutzer ist und das geknackte Passwort `yakuzza` wahrscheinlich zu diesem Benutzer gehört.

## Lateral Movement & Privilegieneskalation (runas -> Administrator)

1.  **Login als `runas` (RDP):** Mit den Anmeldedaten `runas:yakuzza` konnte erfolgreich eine RDP-Verbindung zum System aufgebaut werden.
2.  **CredMan Informationslecks:** Auf dem Desktop des Benutzers `runas` wurde eine PowerShell-Sitzung geöffnet. Der Befehl `cmdkey /list` wurde ausgeführt. Die Ausgabe zeigte gespeicherte Anmeldeinformationen für den Benutzer `RUNAS-PC\Administrator` für die interaktive Anmeldung (`Target: Domain:interactive=RUNAS-PC\Administrator`).
3.  **Ausnutzung von `runas`:** Da die Administrator-Anmeldeinformationen im Credential Manager gespeichert waren, konnte der Benutzer `runas` Programme mit Administrator-Rechten ausführen, ohne das Passwort des Administrators zu kennen, typischerweise mit dem Befehl `runas /user:Administrator <Programm>`.
4.  **Administrator Shell:** Durch die Ausführung von `runas /user:Administrator powershell.exe` oder einer ähnlichen Methode wurde eine PowerShell-Sitzung mit Administrator-Rechten gestartet.
5.  **Root-Flag:** In der Administrator-Sitzung konnte auf den Desktop des Administrators zugegriffen und das Root-Flag aus der Datei `root.txt` ausgelesen werden.

## Flags

*   **user.txt:** `HMV{User_Flag_Was_A_Bit_Bitter}` (Gefunden via LFI in `/Users/runas/Desktop/user.txt`)
*   **root.txt:** Enthielt den Hinweis `HMV{Username_Is_My_Hint}` (Gefunden via LFI in `/Users/Administrator/Desktop/root.txt`). Das finale Root-Flag wurde nach der Privilegieneskalation auf dem Administrator-Desktop gefunden (Inhalt im Writeup nicht gezeigt, aber der Pfad ist klar).

---
