# Kit di lancio ColdPerimeter

Strategia gratuita in una settimana, rivolta a tre nicchie: security/ICS,
tecnici frigoristi e manutentori, sysadmin/MSP del retail.

Messaggio unico, da ripetere ovunque:

> Migliaia di centraline frigo dei supermercati sono raggiungibili da internet.
> ColdPerimeter le trova (in sola lettura) e dà un piano in 7 passi per metterle
> dietro una VPN senza spegnere gli allarmi.

## Calendario

| Giorno | Canale | Tempo |
|---|---|---|
| 0 | GitHub: description, topics, social preview, issue `good first issue` | 30 min |
| 1 | Show HN (mar–gio, 15:00–16:00 ora italiana), poi 2-3 ore a rispondere | 3 h |
| 2-3 | Reddit, un sub al giorno, testo diverso per ognuno | 1 h |
| 3-4 | LinkedIn IT + EN, articolo su Dev.to/Medium | 2 h |
| 5 | PR alle awesome list, submission alle newsletter | 1 h |
| poi | Ogni release = un post breve; risposte alle issue entro 24 h | 10 min/sett. |

Da non fare: lo stesso post su 20 canali lo stesso giorno, comprare stelle,
mostrare IP o negozi reali negli screenshot.

Misurare dopo una settimana: GitHub → Insights → Traffic (referrer e visitatori
unici), poi concentrarsi sul canale che ha reso di più.

---

## Giorno 0: GitHub

**Description (About):**

```text
Find exposed supermarket refrigeration controllers and isolate them behind a WireGuard VPN, without silencing temperature alarms. Read-only.
```

**Topics:**

```text
ics-security ot-security scada danfoss refrigeration wireguard vpn network-scanner iot-security python
```

**Social preview:** Settings → General → Social preview → caricare
`docs/screenshots/results.png`.

**Issue da aprire (label `good first issue` / `help wanted`):**

1. *Support Carel controllers (pCOWeb / Boss)*: fingerprint read-only, stesso
   formato dei Danfoss.
2. *Support Eliwell / Dixell XWEB*: idem.
3. *Translate the interface into another language* (DE, FR, ES).

---

## Giorno 1: Hacker News

**Titolo:**

```text
Show HN: ColdPerimeter – find and isolate exposed supermarket fridge controllers
```

**URL:** `https://github.com/davidebuldrini/coldperimeter`

**Primo commento (da pubblicare subito):**

```text
Hi HN, I built ColdPerimeter after seeing how many supermarket refrigeration
system managers are still reachable straight from the internet, usually
because a maintenance company needed remote access years ago. Vendors have
published advisories for authentication bypass and command execution on some
of these devices; whoever reaches one can change set points or defrost cycles.

The tool is meant for the technician who has to fix this in one visit:

- finds Danfoss AK-SC / AK-SM system managers on the store LAN (slowly, old
  controllers can freeze if probed fast)
- checks exposure: router port forwards, a test from outside, public indexes,
  plus a short on-site checklist for paths a scan can't see (4G routers,
  modems, remote-desktop tools)
- produces a 7-step plan that brings up the VPN and verifies alarms *before*
  closing anything
- generates WireGuard configs for the store and the maintenance center, also
  behind carrier-grade NAT

It is strictly read-only: no password guessing, no writes to controllers or
routers, and it refuses to scan without an authorization record.

Only Danfoss for now. I'd love feedback from people working in OT/ICS or
refrigeration, and pointers to other vendors worth supporting.
```

---

## Giorno 2-3: Reddit

Prima di postare leggere le regole del sub. Dove l'autopromozione è vietata,
fare un post di discussione e mettere il link in un commento.

**r/netsec** (solo link, titolo tecnico):

```text
ColdPerimeter: read-only tool to find internet-exposed Danfoss AK-SC/AK-SM refrigeration controllers and move them behind WireGuard
```

**r/ICS_Security, r/SCADA**

```text
Titolo: Open-source tool to take supermarket refrigeration controllers off the internet

Corpo:
Supermarket refrigeration system managers (Danfoss AK-SC/AK-SM in this first
version) are often port-forwarded for remote maintenance. I wrote a read-only
tool that a technician can run on site: it finds the controllers, checks every
path from the internet (port forwards, outside test, public indexes, 4G
routers) and builds a VPN-first remediation plan that verifies alarms before
anything is closed. MIT, macOS/Windows builds.

Interested in feedback on the plan steps and on which vendors to add next.
<link>
```

**r/sysadmin, r/msp**

```text
Titolo: If you look after retail stores: check whether the fridge controllers are on the internet

Corpo:
Many stores still have the refrigeration manager port-forwarded "for the
maintenance company". I built a free tool that finds them, tells you how they
are reachable and generates WireGuard configs so the maintainer keeps access
without the open port. Read-only, needs written authorization before scanning.
<link>
```

**r/HVAC, r/refrigeration** (taglio pratico, niente gergo security):

```text
Titolo: Free tool for techs: get remote access to store controllers without leaving them open on the internet

Corpo:
If you connect to AK-SC / AK-SM system managers through a port forward, those
devices can be reached by anyone. ColdPerimeter checks the store network,
shows what is exposed and sets up a VPN for you, step by step, making sure
temperature alarms keep working. Free and open source. Feedback from techs who
do this every day would help a lot.
<link>
```

**r/selfhosted** (angolo WireGuard):

```text
Titolo: WireGuard config generator for stores behind CGNAT (hub or direct topology), part of an OT security tool
```

**r/ItalyInformatica** (italiano):

```text
Titolo: Ho fatto uno strumento open source per togliere da internet le centraline frigo dei supermercati

Corpo:
Molti supermercati hanno ancora il supervisore della refrigerazione (Danfoss
AK-SC/AK-SM) esposto su internet per la teleassistenza. ColdPerimeter, in sola
lettura, le trova sulla rete del negozio, verifica da dove sono raggiungibili e
genera un piano in 7 passi con VPN WireGuard, controllando gli allarmi prima di
chiudere qualsiasi accesso. Licenza MIT, build per macOS e Windows, report
anche in italiano. Feedback benvenuti.
<link>
```

---

## Giorno 3-4: LinkedIn

**Italiano:**

```text
Nei supermercati c'è un dispositivo che quasi nessuno guarda: il supervisore
della refrigerazione. Spesso è raggiungibile da internet, messo lì anni fa per
la teleassistenza. Chi ci arriva può cambiare temperature e sbrinamenti e far
buttare la merce di un intero punto vendita.

Ho pubblicato ColdPerimeter, uno strumento gratuito e open source per il
tecnico che deve risolvere il problema in un solo intervento:
→ trova le centraline (Danfoss AK-SC / AK-SM) sulla rete del negozio
→ verifica tutti i percorsi da internet, compresi router 4G e modem
→ prepara un piano in 7 passi: prima la VPN, poi la verifica degli allarmi,
  solo alla fine si chiude l'accesso diretto
→ genera i file WireGuard per negozio e centro assistenza

Solo lettura: niente password provate, niente modifiche a centraline o router.

Se lavori in GDO, manutenzione frigorifera o sicurezza OT mi interessa il tuo
parere.

<link>

#OTsecurity #cybersecurity #GDO #refrigerazione #opensource
```

**English:**

```text
Supermarket refrigeration controllers are often reachable from the internet,
left open years ago for remote maintenance. Anyone who reaches one can change
set points and spoil a whole store's stock.

I released ColdPerimeter, a free, open-source and read-only tool that helps a
technician find these controllers, see every path in from the internet, and
move remote access behind WireGuard without silencing temperature alarms.

Feedback from OT security and refrigeration people is very welcome.

<link>

#OTsecurity #ICS #cybersecurity #retail #opensource
```

**Articolo (Dev.to / Medium / blog), scaletta:**

1. Il problema: centraline frigo esposte, cosa può fare un attaccante.
2. Perché non basta "chiudere la porta": il manutentore perde l'accesso,
   gli allarmi possono smettere di arrivare.
3. Il metodo in 7 passi (VPN prima, allarmi verificati, poi chiusura).
4. Lo strumento: screenshot, comandi, limiti attuali.
5. Come contribuire (nuovi vendor).

---

## Giorno 5: liste e newsletter

**Awesome list (una PR ciascuna):**

- `hslatman/awesome-industrial-control-system-security`, sezione Tools
- una lista awesome-wireguard attiva (cercare su GitHub), sezione Tools
- `sbilly/awesome-security`, sezione Network

Riga da aggiungere:

```text
- [ColdPerimeter](https://github.com/davidebuldrini/coldperimeter) - Read-only tool to find internet-exposed supermarket refrigeration controllers (Danfoss AK-SC/AK-SM) and isolate them behind WireGuard.
```

**Newsletter e siti che accettano segnalazioni:** tl;dr sec, PyCoder's Weekly,
Python Weekly, Console.dev, SANS Internet Storm Center (submit a tip).

**Contatto opzionale:** ricercatori o giornalisti che hanno scritto delle
centraline frigo esposte, proponendo lo strumento come mitigazione pratica.

---

## Dopo il lancio

- Una GIF di 20 secondi (scan → piano → VPN) in cima al README aumenta la
  conversione visitatore → stella.
- Ogni nuovo vendor supportato è un nuovo annuncio.
- Talk brevi a eventi gratuiti: OWASP Italy Day, No Hat, BSides, meetup locali.
