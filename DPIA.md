# Posouzeni vlivu na ochranu osobnich udaju (DPIA)
## Cl. 35 GDPR - Data Protection Impact Assessment

**Spravce:** HOFO Media Group s.r.o. (ICO: 07900171)
**Aplikace:** MujCyklus - tracker menstruacniho cyklu
**Datum provedeni:** 30. 3. 2026
**Provedl:** Jan Formanek, jednatel
**Verze:** 1.0

---

## 1. Proc je DPIA povinne

DPIA je **povinne** podle cl. 35 odst. 3 GDPR, protoze zpracovani zahrnuje:

- **Zvlastni kategorii osobnich udaju** (cl. 9 GDPR) - udaje o zdravotnim stavu (menstruacni cyklus, symptomy, nalady)
- **Systematicke zpracovani** - pravidelne zaznamenavani a automaticke predikce
- **Zpracovani ve velkem rozsahu** - potencialne velky pocet uzivatelu

Toto zpracovani je rovnez uvedeno na seznamu operaci vyzadujicich DPIA vydanem UOOU.

---

## 2. Popis zpracovani

### 2.1 Povaha zpracovani
Webova aplikace pro sledovani menstruacniho cyklu, ktera shromazduje, uklada a analyzuje osobni udaje vcetne udaju o zdravotnim stavu.

### 2.2 Rozsah zpracovani
| Aspekt | Popis |
|--------|-------|
| **Typy udaju** | Email, jmeno, vek, menstruacni data, nalady, symptomy, antikoncepce, AI analyzy |
| **Zvlastni kategorie** | ANO - udaje o zdravotnim stavu (cl. 9 GDPR) |
| **Pocet subjektu** | Ocekavane stovky az tisice uzivatelu |
| **Geograficky rozsah** | Primarne CR, potencialne celoevropsky |
| **Frekvence** | Denni zaznam dat uzivateli |
| **Doba uchovani** | Do smazani uctu (data cyklu), 5 let (souhlasy) |

### 2.3 Kontext zpracovani
- Uzivatele dobrovolne zadavaji intimni zdravotni data
- Data jsou citliva a mohou odhalit zdravotni stav, plodnost, tehotenstvi
- Existuje moznot sdileni dat s partnerem
- AI analyza odesila anonymizovana data tretí strane (Anthropic)

### 2.4 Ucely zpracovani
1. Sledovani a predikce menstruacniho cyklu
2. Zaznamenavani nalad a symptomu
3. AI analyza vzorcu v cyklu
4. Sdileni s partnerem
5. Export dat pro lekare
6. Emailova upozorneni

---

## 3. Posouzeni nezbytnosti a primernosti

### 3.1 Pravni zaklad
| Kategorie | Pravni zaklad | Hodnoceni |
|-----------|--------------|-----------|
| Zdravotni data | Vyslovny souhlas (cl. 9/2/a) | **PRIMERENE** - souhlas je informovany, svobodny, odvolatelny |
| Ucet | Plneni smlouvy (cl. 6/1/b) | **PRIMERENE** - nezbytne pro provoz sluzby |
| Bezpecnost | Opravneny zajem (cl. 6/1/f) | **PRIMERENE** - ochrana pred utoky |

### 3.2 Minimalizace dat
- Jmeno a vek jsou volitelne
- AI analyza neodesila email/jmeno (pouze anonymizovana data cyklu)
- Partner vidi pouze uzivatelkou vybrane kategorie
- Login attempts se mazi po 24 hodinach

### 3.3 Presnost dat
- Uzivatele sami zadavaji a mohou editovat svá data
- Predikce jsou oznaceny jako orientacni
- AI analyza obsahuje disclaimer "nenahrazuje lekare"

### 3.4 Omezeni uchovani
- Ucet: do smazani + 30 dni
- Data cyklu: do smazani uctu
- AI analyzy: 12 mesicu
- Login attempts: 24 hodin
- Souhlasy: 5 let (pravni povinnost)

### 3.5 Prava subjektu
| Pravo | Implementace | Stav |
|-------|-------------|------|
| Pristup (cl. 15) | GET /api/gdpr/export-data | Implementovano |
| Oprava (cl. 16) | Editace profilu v aplikaci | Implementovano |
| Vymazani (cl. 17) | POST /api/gdpr/delete-account | Implementovano |
| Omezeni (cl. 18) | Na zadost emailem | Dostupne |
| Prenositelnost (cl. 20) | JSON export | Implementovano |
| Odvolani souhlasu | Smazani uctu | Implementovano |

---

## 4. Identifikace a posouzeni rizik

### 4.1 Rizika pro subjekty udaju

| # | Riziko | Pravdepodobnost | Zavaznost | Celkova uroven |
|---|--------|-----------------|-----------|----------------|
| R1 | **Unik zdravotnich dat** - neautorizovany pristup k DB | Nizka | Vysoka | **STREDNI** |
| R2 | **Zneuziti dat partnerem** - partner sdili data bez souhlasu | Stredni | Stredni | **STREDNI** |
| R3 | **Odhaleni intimnich informaci** - tehotenstvi, zdravotni problemy | Nizka | Vysoka | **STREDNI** |
| R4 | **Nepresne predikce** - chybna predikce plodnosti/menstruace | Stredni | Stredni | **STREDNI** |
| R5 | **Pristup treti strany** - Anthropic, Supabase, Google | Nizka | Vysoka | **STREDNI** |
| R6 | **Brute-force utok na ucet** | Stredni | Vysoka | **STREDNI** |
| R7 | **Ztrata dat** - selhani databaze | Nizka | Stredni | **NIZKA** |

### 4.2 Detailni analyza klicovych rizik

#### R1: Unik zdravotnich dat
- **Scenar:** Utocnik ziska pristup k databazi nebo API
- **Dopad:** Vyznamny - zdravotni data jsou zvlastni kategorii, mohou byt zneuzita k diskriminaci
- **Existujici opatreni:** HTTPS, bcrypt, session auth, CSRF, SSL DB
- **Dalsi doporucena opatreni:** Sifrovani dat v klidu (db-level encryption), pravidelne bezpecnostni audity

#### R3: Odhaleni intimnich informaci
- **Scenar:** Unauthorized pristup k uctu odhalí tehotenstvi, zdravotni problemy
- **Dopad:** Vyznamny - potencialni socialni, pracovni nebo rodinne nasledky
- **Existujici opatreni:** Silna autentizace, rate limiting
- **Dalsi doporucena opatreni:** 2FA (budouci), oznameni o prihlaseni z noveho zarizeni

#### R5: Pristup treti strany
- **Scenar:** Treti strana (Anthropic/Supabase) zneuzije nebo ztrati data
- **Dopad:** Stredni az vysoky
- **Existujici opatreni:** AI data jsou anonymizovana (bez emailu/jmena), SSL pripojeni
- **Dalsi doporucena opatreni:** Pravidelna kontrola DPA s dodavateli

---

## 5. Opatreni ke snizeni rizik

### 5.1 Implementovana opatreni

| Opatreni | Resi riziko | Stav |
|----------|-------------|------|
| HTTPS/TLS sifrovani | R1, R5 | Implementovano |
| bcrypt hash hesel (12 kol) | R1, R6 | Implementovano |
| Session autentizace + HttpOnly cookies | R1, R6 | Implementovano |
| CSRF tokenova ochrana | R1 | Implementovano |
| Rate limiting (10/15min) | R6 | Implementovano |
| Email verifikace pri registraci | R6 | Implementovano |
| Vyslovny souhlas pro zdravotni data | Pravni | Implementovano |
| Pravo na vymazani (1 klik) | Pravni | Implementovano |
| JSON export dat | Pravni | Implementovano |
| Anonymizace AI dat (bez emailu/jmena) | R5 | Implementovano |
| Uzivatelska kontrola sdileni | R2 | Implementovano |
| Disclaimer "neni lekarska rada" | R4 | Implementovano |
| Automaticky cleanup stary login attempts | R1 | Implementovano |
| Zaznamy souhlasu s IP a casem | Pravni | Implementovano |
| Vekova restrikce 15+ | Pravni | Implementovano |

### 5.2 Planovana opatreni

| Opatreni | Resi riziko | Priorita | Termin |
|----------|-------------|----------|--------|
| Dvojfaktorova autentizace (2FA) | R1, R6 | Vysoka | Q3 2026 |
| Sifrovani dat v klidu | R1 | Stredni | Q4 2026 |
| Oznameni o prihlaseni z noveho zarizeni | R1 | Stredni | Q3 2026 |
| Automaticka detekce anomalii v pristupu | R1, R6 | Nizka | Q1 2027 |
| Pravidelny bezpecnostni audit | R1-R7 | Vysoka | Kazdych 12 mesicu |

---

## 6. Konzultace

### 6.1 Konzultace s dozorovou autoritou
Na zaklade posouzeni a implementovanych opatreni **nepovazujeme za nutne** konzultovat s UOOU pred zahajenim zpracovani (cl. 36 GDPR), protoze:
- Jsou implementovana dostatecna technicka opatreni
- Zpracovani je zalozeno na vyslovnem souhlasu
- Subjektum jsou zajistena vsechna prava
- Rezidualni rizika jsou snizena na prijatelnou uroven

### 6.2 Kontakt na dozorovy urad
Urad pro ochranu osobnich udaju (UOOU)
- Adresa: Pplk. Sochora 27, 170 00 Praha 7
- Email: posta@uoou.cz
- Web: www.uoou.cz

---

## 7. Zaver

Na zaklade tohoto posouzeni:

1. **Zpracovani je primerene** ucelu sledovani menstruacniho cyklu
2. **Pravni zaklad je spravne zvolen** - vyslovny souhlas pro zdravotni data
3. **Technicka opatreni jsou dostatecna** pro soucasny rozsah zpracovani
4. **Prava subjektu jsou plne zajistena** vcetne smazani a exportu
5. **Rezidualni rizika jsou prijatelna** po implementaci opatreni

**Doporuceni:** Implementovat 2FA a sifrovani v klidu do Q4 2026. Provest bezpecnostni audit do 12 mesicu.

---

**Podpis:** Jan Formanek, jednatel HOFO Media Group s.r.o.
**Datum:** 30. 3. 2026

*Tento dokument bude revidovan pri vyznamnych zmenach zpracovani nebo alespon jednou rocne.*
