# Attacking Web Applications with FFUF

Notes from HTB module **Attacking Web Applications with FFUF**.

---

## Directory Fuzzing

Enumerate hidden directories on a web server.

Common wordlists for directory fuzzing include:

- directory-list-2.3-small/medium/big.txt
- raft-small/medium/large-directories.txt

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ
```

Some wordlists contain comments at the beginning of the document. These comments may clutter the results. Utilize the '**-ic**' flag to ignore comments.

```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/FUZZ -ic
```

---

## Extension Fuzzing

Enumerate file extensions on a web server. Extension fuzzing is usually performed before page fuzzing.

Common wordlists for extension fuzzing include:

- web-extensions.txt
- web-extensions-big.txt
- raft-small/medium/large-extensions.txt
- file-extensions-all-cases.txt

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/<FILE>FUZZ
```

The **index** file is present on most web servers and often used for extension fuzzing:

```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://94.237.61.242:8080/indexFUZZ
```

---

## Page Fuzzing

Enumerate hidden pages on a web server. Leveraging the information found during the extension fuzzing process, we can proceed by fuzzing for pages.

Common wordlists for page fuzzing include the same ones used for directory fuzzing.

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ.<EXT>
```

```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/blog/FUZZ.php -ic
```

# Databaser L0003B (LTU)

Anteckningar och uppgifter från kursen Databaser L0003B på LTU. Kursen behandlar relationsdatabaser med fokus på SQL och implementation i VB.

---

## Uppgift 1 – L0003B (Sammanfattning)

Uppgiften går ut på att bygga en Windows Forms-applikation i **VB.NET** som kommunicerar med en SQL Server-databas via **ADO.NET**.

Syftet är att träna på:

- Kommunikation mellan program och databas
- Att konstruera SQL-satser
- Att hantera CRUD-operationer (Create, Read, Update, Delete)
- Att upprätthålla objektintegritet i databasen

### Databasstruktur (krav)

Databasen **L0003B** består av tre tabeller:

| Tabell           | Primärnyckel     | Beskrivning               |
| ---------------- | ---------------- | ------------------------- |
| `Elevxxxxxx`     | `pnr`            | Elevens personuppgifter   |
| `Kursxxxxxx`     | `kursnamn`       | Kurser                    |
| `KursElevxxxxxx` | `pnr + kursnamn` | Kopplingstabell elev–kurs |

**Inga constraints skapas i databasen** – programmet ska hantera reglerna.

### Funktionskrav

Programmet ska klara följande regler:

- Ta bort en elev → alla den elevens kursval tas bort
- En kurs får inte tas bort om det finns elever registrerade
- Dubbletter får inte förekomma i någon tabell
- Ändring av primärnycklar (pnr eller kursnamn) ska slå igenom i kopplingstabellen

### SQL-implementation

De SQL-satser som används för uppgiften finns i följande filer:

- `frmElev.vb` – hantering av elever
- `frmKurs.vb` – hantering av kurser
- `frmOppna.vb` – öppning och visning av data

- Kommunikation mellan program och databas
- Att konstruera SQL-satser
- Att hantera CRUD-operationer (Create, Read, Update, Delete)
- Att upprätthålla objektintegritet i databasen

### Databasstruktur (krav)

Databasen **L0003B** består av tre tabeller:

| Tabell           | Primärnyckel     | Beskrivning               |
| ---------------- | ---------------- | ------------------------- |
| `Elevxxxxxx`     | `pnr`            | Elevens personuppgifter   |
| `Kursxxxxxx`     | `kursnamn`       | Kurser                    |
| `KursElevxxxxxx` | `pnr + kursnamn` | Kopplingstabell elev–kurs |

**Inga constraints skapas i databasen** – programmet ska hantera reglerna.

### Funktionskrav

Programmet ska klara följande regler:

- Ta bort en elev → alla den elevens kursval tas bort
- En kurs får inte tas bort om det finns elever registrerade
- Dubbletter får inte förekomma i någon tabell
- Ändring av primärnycklar (pnr eller kursnamn) ska slå igenom i kopplingstabellen

### SQL-implementation

De SQL-satser som används för uppgiften finns i följande filer:

- `frmElev.vb` – hantering av elever
- `frmKurs.vb` – hantering av kurser
- `frmOppna.vb` – öppning och visning av data
