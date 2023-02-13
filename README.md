# Penetration-Tester-Begriffe

## Penetration Tester vs. Red Teamer
**Penetrationstester** sind IT-Sicherheitsexperten, die gezielt nach Schwachstellen in Systemen suchen, um die IT-Sicherheit einer Organisation zu verbessern. Sie führen geplante Tests durch, um die Sicherheit von Netzwerken, Anwendungen und Systemen zu überprüfen. Dabei verwenden sie Tools und Techniken, um mögliche Sicherheitslücken aufzudecken.

**Red Teamer** hingegen sind erfahrene Sicherheitsexperten, die realitätsnahe Angriffe auf IT-Systeme durchführen, um deren Widerstandsfähigkeit zu testen. Sie simulieren Angriffe, die von echten Bedrohungen ausgehen könnten, und gehen dabei so vor, wie ein echter Angreifer. Ihr Ziel ist es, die tatsächlichen Sicherheitsrisiken einer Organisation zu identifizieren und zu bewerten, indem sie die Abwehrmechanismen des Unternehmens testen.

## SOC
SOC steht für "Security Operations Center". Es handelt sich um eine Einheit innerhalb eines Unternehmens oder einer Organisation, die für die Überwachung und Verwaltung der IT-Sicherheit verantwortlich ist. Ein SOC kann eine Vielzahl von Aufgaben ausführen, darunter Überwachung von Sicherheitsereignissen, Überwachung von Netzwerken, Überwachung von Systemen und Anwendungen, Überwachung von Benutzeraktivitäten und Überwachung von Bedrohungen. Es arbeitet eng mit anderen Abteilungen, wie dem IT-Betrieb und der IT-Sicherheit, zusammen, um sicherzustellen, dass das Unternehmen vor IT-Sicherheitsbedrohungen geschützt ist und dass mögliche Bedrohungen schnell erkannt und behoben werden können.

Ein Security Operations Center (SOC) ist ein Team von Cyber-Sicherheitsfachleuten, das das Netzwerk und seine Systeme überwacht, um bösartige Cyber-Sicherheitsereignisse zu erkennen. Einige der wichtigsten Interessensgebiete eines SOC sind:

**Schwachstellen**: Sobald eine System Schwachstelle (Schwäche) entdeckt wird, ist es unerlässlich, diese durch die Installation eines passenden Updates oder Patches zu beheben. Wenn keine Lösung verfügbar ist, müssen die notwendigen Maßnahmen ergriffen werden, um einem Angreifer das Ausnutzen zu verhindern. Obwohl das Beseitigen von Schwachstellen von großem Interesse für ein SOC ist, ist es nicht zwingend ihnen zugeordnet. 

**Verstöße gegen Richtlinien**: Eine Sicherheitsrichtlinie kann als eine Reihe von Regeln verstanden werden, die für den Schutz des Netzwerks und der Systeme erforderlich sind. Beispielsweise könnte es ein Verstoß gegen die Richtlinie sein, wenn Benutzer anfangen, vertrauliche Unternehmensdaten auf einen Online-Speicherdienst hochzuladen. 

**Unauthorisierte Aktivitäten**: Nehmen Sie den Fall an, in dem der Login-Name und das Passwort eines Benutzers gestohlen werden und der Angreifer sie verwendet, um sich in das Netzwerk einzuloggen. Ein SOC muss solch ein Ereignis so schnell wie möglich erkennen und blockieren, bevor weiterer Schaden entsteht. 

**Netzwerk-Eindringungen**: Egal wie gut Ihre Sicherheit ist, es besteht immer die Chance für eine Eindringung. Eine Eindringung kann vorkommen, wenn ein Benutzer auf einen bösartigen Link klickt oder wenn ein Angreifer einen öffentlichen Server ausnutzt. Auf jeden Fall muss bei einer Eindringung so schnell wie möglich eine Erkennung erfolgen, um weiteren Schaden zu verhindern.

## Threat Intelligence (Bedrohungs-Intelligence)

Im Kontext von Bedrohungs-Intelligence bezieht sich Intelligence auf Informationen, die über aktuelle und potentielle Feinde gesammelt werden. Eine Bedrohung ist jede Aktion, die ein System stören oder beeinträchtigen kann. Bedrohungs-Intelligence zielt darauf ab, Informationen zu sammeln, um das Unternehmen besser auf potenzielle Angreifer vorzubereiten. Das Ziel wäre eine bedrohungs-informierte Verteidigung. Verschiedene Unternehmen haben verschiedene Gegner. Einige Gegner könnten versuchen, Kundendaten von einem Mobilfunkbetreiber zu stehlen; andere Gegner sind jedoch an einer Unterbrechung der Produktion in einer Raffinerie interessiert. Beispiele für Gegner sind eine staatliche Cyberarmee, die aus politischen Gründen arbeitet, und eine Ransomware-Gruppe, die aus finanziellen Zwecken handelt. Basierend auf dem Unternehmen (Ziel) können wir mit Gegnern rechnen.

Intelligence benötigt Daten. Daten müssen gesammelt, verarbeitet und analysiert werden. Die Datensammlung erfolgt aus lokalen Quellen wie Netzwerk-Logs und öffentlichen Quellen wie Foren. Die Verarbeitung der Daten zielt darauf ab, sie in ein für die Analyse geeignetes Format zu arrangieren. Die Analysephase versucht, mehr Informationen über die Angreifer und ihre Motive zu finden, und zielt außerdem darauf ab, eine Liste von Empfehlungen und umsetzbaren Schritten zu erstellen.

Durch das Lernen über Ihre Gegner können Sie deren Taktiken, Techniken und Verfahren kennen. Als Ergebnis der Bedrohungs-Intelligence identifizieren wir den Bedrohungs-Akteur (Gegner), prognostizieren seine Aktivitäten und können somit seine Angriffe abmildern und eine Reaktionsstrategie vorbereiten.

## Digitalforensik
Forensik bezieht sich auf den Einsatz von Wissenschaft bei der Untersuchung von Straftaten und der Feststellung von Fakten. Mit dem Einsatz und der Verbreitung digitaler Systeme, wie Computern und Smartphones, entstand ein neuer Zweig der Forensik, um damit verbundene Verbrechen zu untersuchen: Computerforensik, die später zur Digitalforensik weiterentwickelt wurde.

Im Rahmen der Verteidigung im Bereich der Informationssicherheit richtet sich der Fokus der Digitalforensik auf die Analyse von Beweisen für einen Angriff und seine Täter sowie andere Bereiche wie Diebstahl geistigen Eigentums, Cyber-Espionage und Besitz unerlaubter Inhalte. Folglich wird sich die Digitalforensik auf unterschiedliche Bereiche konzentrieren, wie zum Beispiel:

**Dateisystem**: Die Analyse eines digitalen Forensikbildes (Low-Level-Kopie) eines Systemspeichers liefert viele Informationen, wie installierte Programme, erstellte Dateien, teilweise überschriebene Dateien und gelöschte Dateien. 

**Systemspeicher**: Wenn ein Angreifer sein bösartiges Programm im Speicher ausführt, ohne es auf die Festplatte zu speichern, ist ein Forensikbild (Low-Level-Kopie) des Systemspeichers die beste Möglichkeit, dessen Inhalt zu analysieren und mehr über den Angriff zu erfahren. 

**Systemprotokolle**: Jeder Client- und Servercomputer führt unterschiedliche Protokolldateien über das, was vor sich geht. Protokolldateien liefern viele Informationen darüber, was auf einem System passiert ist. Einige Spuren bleiben erhalten, selbst wenn der Angreifer versucht, seine Spuren zu löschen. 

**Netzwerkprotokolle**: Protokolle der Netzwerkpakete, die ein Netzwerk durchlaufen haben, würden helfen, mehr Fragen darüber zu beantworten, ob ein Angriff stattfindet und wie er aussieht.


## Incident Response
Ein Vorfall bezieht sich in der Regel auf einen Datenbruch oder einen Cyberangriff; in einigen Fällen kann es jedoch etwas weniger kritisch sein, wie z.B. eine Fehlkonfiguration, ein Eindringversuch oder eine Verstoß gegen eine Regel. Beispiele für einen Cyberangriff sind, dass ein Angreifer unser Netzwerk oder unsere Systeme unzugänglich macht, die öffentliche Website verändert (defacing) und Daten stiehlt (Datenbruch). Wie würden Sie auf einen Cyberangriff reagieren? Die Einsatzreaktion legt die Methode fest, die befolgt werden sollte, um einen solchen Fall zu bearbeiten. Das Ziel ist es, den Schaden so gering wie möglich zu halten und in möglichst kurzer Zeit wiederherzustellen. Idealerweise entwickeln Sie einen bereits bereiten Plan für die Einsatzreaktion.

Die vier wichtigsten Phasen des Einsatzreaktionsprozesses sind:

**Vorbereitung (Preparation)**: Hier ist ein Team erforderlich, das ausgebildet und bereit ist, Vorfälle zu bearbeiten. Idealerweise werden verschiedene Maßnahmen getroffen, um Vorfälle von vornherein zu verhindern. 

**Erkennung und Analyse (Detection and Analysis)**: Das Team verfügt über die erforderlichen Ressourcen, um jeden Vorfall zu erkennen, und es ist unerlässlich, jeden erkannten Vorfall weiter zu analysieren, um seine Schwere zu erfassen. 

**Beschränkung, Beseitigung und Wiederherstellung (Containment, Eradication, and Recovery)**: Sobald ein Vorfall erkannt wurde, ist es von entscheidender Bedeutung, dass er nicht auf andere Systeme ausstrahlt, ihn zu beseitigen und die betroffenen Systeme wiederherzustellen. Wenn wir zum Beispiel feststellen, dass ein System von einem Computer-Virus befallen ist, möchten wir den Virus (beschränken) von der Ausbreitung auf andere Systeme aufhalten, ihn reinigen (beseitigen) und eine ordnungsgemäße Systemwiederherstellung sicherstellen. 

**Nach-Vorfall-Aktivität (Post-Incident Activity)**: Nach erfolgreicher Wiederherstellung wird ein Bericht erstellt und die gelernte Lektion geteilt, um ähnliche zukünftige Vorfälle zu verhindern.

## Malware Analysis
Malware bezieht sich auf bösartige Software. Software bezieht sich auf Programme, Dokumente und Dateien, die man auf einer Festplatte speichern oder über das Netzwerk senden kann. Malware umfasst viele Typen, wie:

**Virus ist ein Stück Code** (Teil eines Programms), das sich an ein Programm anhängt. Es ist so entworfen, dass es sich von einem Computer zum anderen verbreitet, und es funktioniert, indem es Dateien verändert, überschreibt und löscht, sobald es einen Computer infiziert. Das Ergebnis reicht von einem langsamen Computer bis zu einem unbrauchbaren Computer. Ein Trojanisches 

**Pferd ist ein Programm**, das eine wünschenswerte Funktion anzeigt, aber unter der Oberfläche eine bösartige Funktion verbirgt. Beispielsweise könnte ein Opfer einen Videoplayer von einer unseriösen Website herunterladen, die dem Angreifer die vollständige Kontrolle über sein System gibt. 

**Ransomware** ist ein bösartiges Programm, das die Dateien des Benutzers verschlüsselt. Verschlüsselung macht die Dateien ohne das Wissen des Verschlüsselungspassworts unlesbar. Der Angreifer bietet dem Benutzer das Verschlüsselungspasswort an, wenn der Benutzer bereit ist, ein "Lösegeld" zu zahlen.



# # Careers in Cyber

## Security Analyst
Ein Security Analyst ist eine Person, die für die Überwachung und Überprüfung von Computersystemen und Netzwerken zuständig ist, um sicherzustellen, dass sie vor Bedrohungen und Angriffen geschützt sind. Die Hauptaufgabe eines Security Analysts besteht darin, Bedrohungen zu erkennen, zu bewerten und zu reagieren, indem sie Maßnahmen ergreifen, um die Systeme und Netzwerke zu schützen. Dazu gehören die Überwachung von Netzwerk- und Systemaktivitäten, die Überprüfung von Sicherheitsereignissen, die Durchführung von Bedrohungsanalysen und die Empfehlung von Maßnahmen zur Verbesserung der Sicherheit. Ein Security Analyst arbeitet eng mit anderen Teams wie dem Netzwerkadministrator, dem IT-Manager und dem Informationssicherheitsteam zusammen, um sicherzustellen, dass die IT-Infrastruktur optimal geschützt ist.

## Security Engineer
Ein Security Engineer ist ein Experte im Bereich Informationssicherheit, der verantwortlich ist für die Planung, Entwicklung und Implementierung von Sicherheitslösungen für ein Unternehmen oder eine Organisation.

Einige der Hauptaufgaben eines Security Engineers sind:

-   Überwachung und Überprüfung der Informationssicherheitssysteme, um sicherzustellen, dass sie ordnungsgemäß funktionieren und potenzielle Bedrohungen abwehren.
-   Analyse von Bedrohungen und Sicherheitsrisiken, um Maßnahmen zur Verhinderung von Sicherheitsverletzungen zu empfehlen.
-   Konzeption und Implementierung von Informationssicherheitstechnologien, einschließlich Firewalls, Intrusion Detection Systems, Zugriffskontrollsysteme und Verschlüsselungstechnologien.
-   Überwachung und Überprüfung von Compliance-Anforderungen für Informationssicherheit, wie z.B. Branchenstandards oder gesetzliche Vorschriften.
-   Überwachung und Überprüfung von Sicherheitsaudits und Überwachungstests, um sicherzustellen, dass alle Systeme und Prozesse ordnungsgemäß funktionieren.

## Incident Responder
Ein Incident Responder ist eine Person, die verantwortlich ist für das reaktive Management von Sicherheitsvorfällen. Sie arbeiten innerhalb eines Unternehmens oder einer Organisation und sind dafür zuständig, auf Vorfallmeldungen zu reagieren, die Auswirkungen auf die IT-Sicherheit haben können.

Ihre Hauptaufgaben sind:

1.  Überwachung von Sicherheitssystemen und Netzwerken auf Vorfälle.
2.  Untersuchung und Analyse von Sicherheitsvorfällen, um deren Schweregrad zu bestimmen.
3.  Eindämmung von Sicherheitsvorfällen, um eine weitere Ausbreitung zu verhindern.
4.  Beseitigung von Bedrohungen und Wiederherstellung des Systems.
5.  Dokumentation und Berichterstattung über die Incident-Response-Aktivitäten.
6.  Überwachung und Überprüfung der vorbeugenden Maßnahmen, um zukünftige Vorfälle zu verhindern.

## Digital Forensics Examiner
Ein Digital Forensics Examiner ist eine Person, die auf dem Gebiet der digitalen Forensik spezialisiert ist. Die Hauptaufgabe eines Digital Forensics Examiners ist es, digitale Beweise in Zusammenhang mit Verbrechen oder Vorwürfen zu sammeln, zu analysieren und zu präsentieren. Dies kann beinhalten:

-   Die Durchführung einer tiefen Analyse von Computersystemen und digitalen Geräten
-   Überprüfung von Daten und Dateien auf Beweisstücke
-   Rekonstruktion von Ereignissen auf einem digitalen System
-   Zusammenstellung und Präsentation von Berichten über die gefundenen Beweise
-   Zusammenarbeit mit Strafverfolgungsbehörden und Gerichten bei der Beweisaufnahme.

## Malware Analyst
Ein Malware-Analyst ist eine Person, die sich mit der Analyse von Malware beschäftigt. Dies beinhaltet die Untersuchung von Malware-Code, um die Funktionsweise zu verstehen und zu bestimmen, wie es sich auf Computer-Systeme auswirken kann. Einige der wichtigsten Aufgaben eines Malware-Analysten sind:

1.  Untersuchung von Malware-Proben: Der Analytiker muss die Malware untersuchen und analysieren, um die Art des Angriffs und das Ziel der Malware zu bestimmen.
    
2.  Reverse Engineering von Malware-Code: Der Analytiker muss in der Lage sein, den Malware-Code umzukehren und zu verstehen, wie er funktioniert und wie er sich auf Computer-Systeme auswirken kann.
    
3.  Dokumentation von Befunden: Der Analytiker muss die Ergebnisse seiner Analyse dokumentieren und sicherstellen, dass alle relevanten Informationen für zukünftige Referenzen aufgezeichnet werden.
    
4.  Entwicklung von Schutzmaßnahmen: Basierend auf den gewonnenen Erkenntnissen muss der Analytiker empfehlen, wie man sich gegen diese Art von Malware schützen kann.

## Penetration Tester
Ein Penetrationstester ist ein Sicherheitsexperte, dessen Hauptaufgabe es ist, die Schwachstellen und Sicherheitslücken in einem System oder Netzwerk zu identifizieren. Dies geschieht, indem sie das System oder Netzwerk absichtlich angreifen, um Schwachstellen aufzudecken, bevor sie von böswilligen Angreifern ausgenutzt werden können. Die Hauptaufgaben eines Penetrationstesters umfassen:

-   Durchführung von Sicherheitstests: Sie führen Penetrationstests auf einem System oder Netzwerk durch, um Schwachstellen zu identifizieren.
-   Identifizierung von Schwachstellen: Sie analysieren die Systeme und Netzwerke und identifizieren potenzielle Schwachstellen, die von Angreifern ausgenutzt werden können.
-   Dokumentation von Befunden: Sie dokumentieren die erkannten Schwachstellen und erstellen Berichte über ihre Befunde und Empfehlungen zur Behebung.
-   Zusammenarbeit mit Entwicklungsteams: Sie arbeiten eng mit Entwicklungsteams zusammen, um Schwachstellen zu beheben und das System oder Netzwerk zu verbessern.

## Red Teamer
Ein Red Teamer ist ein professioneller Hacker, der sich auf Penetrationstests spezialisiert hat. Die Hauptaufgabe eines Red Teamers besteht darin, die Sicherheit eines Unternehmens oder einer Organisation auf die Probe zu stellen, indem er versucht, in das Netzwerk einzudringen und Schwachstellen zu identifizieren. Dies geschieht normalerweise durch die Durchführung von realistischen Angriffsszenarien, die dem Angreifer ähneln, um zu testen, wie gut das Unternehmen gegen Angriffe geschützt ist. Nach Abschluss des Tests erstellt der Red Teamer einen umfassenden Bericht über seine Ergebnisse und gibt Empfehlungen, wie die Schwachstellen behoben werden können.

# CyberSecurity

## OSSTMM
OSSTMM steht für "Open Source Security Testing Methodology Manual". Es handelt sich dabei um ein Open-Source-Sicherheits-Testing-Methodologie-Handbuch, das als Rahmenwerk für Penetrationstests verwendet wird. Das Ziel des OSSTMM ist es, eine umfassende und systematische Methode zur Überprüfung der Sicherheit von IT-Systemen bereitzustellen. Es beschreibt detailliert, wie man ein Netzwerk oder eine Anwendung auf Sicherheitslücken untersucht und bewertet. Mit OSSTMM können Penetrationstester ihre Tests standardisieren und ihre Ergebnisse überprüfbar machen.

## OWASP
OWASP steht für Open Web Application Security Project. Es ist eine weltweite, gemeinnützige Organisation, die sich auf die Verbesserung der Sicherheit von Web-Anwendungen konzentriert. Die Mission von OWASP besteht darin, Unternehmen, Entwickler und Benutzer über die neuesten Bedrohungen und Risiken für Web-Sicherheit zu informieren und die Entwicklung von sicheren Anwendungen zu fördern. OWASP bietet eine Vielzahl von Tools, Methoden, Dokumenten und Ressourcen, die Unternehmen und Entwickler bei der Bewertung und Verbesserung der Sicherheit ihrer Web-Anwendungen unterstützen.

## NIST Cybersecurity Framework
Das NIST Cybersecurity Framework (CSF) ist ein Rahmenwerk für die Bewertung und Verbesserung der Cybersecurity einer Organisation. Es wurde von der US-Regierungsbehörde National Institute of Standards and Technology (NIST) entwickelt und bietet Unternehmen eine umfassende Methode zur Bewertung ihrer Cybersecurity-Praktiken und -Prozesse.

Das CSF besteht aus fünf Hauptkategorien: Identifikation, Schutz, Detektion, Reaktion und Wiederherstellung. Jede Kategorie enthält eine Reihe von Prozessen und Praktiken, die dazu beitragen, eine starke Cybersecurity zu gewährleisten. Ziel des Frameworks ist es, Unternehmen dabei zu unterstützen, ihre Risiken zu identifizieren und zu bewerten und entsprechende Maßnahmen zu ergreifen, um ihre Systeme und Daten zu schützen.

Das NIST CSF ist ein bewährter Ansatz für die Verwaltung von Cybersecurity-Risiken und hat sich bei vielen Organisationen als nützlich erwiesen, die sich bemühen, ihre Cybersecurity-Praktiken und -Prozesse zu verbessern.

## NCSC CAF
Das National Cyber Security Centre Cyber Assessment Framework (NCSC CAF) ist ein Rahmenwerk, das von dem National Cyber Security Centre (NCSC) entwickelt wurde. Es dient als Leitfaden für Organisationen, die ihre Cyber-Sicherheit bewerten und verbessern möchten. Das NCSC CAF umfasst Empfehlungen für die Bereiche Organisation, Technik, Prozesse und Verantwortung. Ziel des NCSC CAF ist es, Organisationen dabei zu unterstützen, ein Verständnis für ihre Cyber-Sicherheitsrisiken zu entwickeln und entsprechende Maßnahmen zu ergreifen, um sich vor Cyber-Angriffen und Datenverlusten zu schützen.






