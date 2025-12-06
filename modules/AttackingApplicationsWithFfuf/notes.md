# Attacking Web Applications with FFUF

Notes from HTB module **Attacking Web Applications with FFUF**.

---

## Directory Fuzzing

Enumerate hidden directories on a web server. Common wordlists for directory fuzzing include:

- directory-list-2.3-small/medium/big.txt
- raft-small/medium/large-directories.txt

Basic syntax for directory fuzzing:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ
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
