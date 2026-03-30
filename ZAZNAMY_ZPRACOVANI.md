# Zaznamy o cinnostech zpracovani (cl. 30 GDPR)

**Spravce:** HOFO Media Group s.r.o. (ICO: 07900171)
**Aplikace:** MujCyklus - tracker menstruacniho cyklu
**Datum vytvoreni:** 30. 3. 2026
**Posledni aktualizace:** 30. 3. 2026

---

## 1. Registrace a sprava uctu

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Vytvoreni a sprava uzivatelskeho uctu |
| **Kategorie subjektu** | Registrovani uzivatele (zeny 15+) |
| **Kategorie udaju** | Email, heslo (bcrypt hash), jmeno, vek |
| **Pravni zaklad** | Cl. 6 odst. 1 pism. b) GDPR - plneni smlouvy |
| **Prijemci** | Supabase (DB), Google (SMTP pro overovaci emaily) |
| **Prenosy do treti zeme** | USA (Supabase, Google) - standardni smluvni dolozky |
| **Lhuta pro vymazani** | Do smazani uctu + 30 dni |
| **Technicka opatreni** | HTTPS, bcrypt hash, session auth, CSRF, rate limiting |

## 2. Sledovani menstruacniho cyklu

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Zaznam a predikce menstruacniho cyklu, nalad a symptomu |
| **Kategorie subjektu** | Registrovani uzivatele |
| **Kategorie udaju** | **ZVLASTNI KATEGORIE** - udaje o zdravotnim stavu: menstruace (datum, delka, intenzita), nalady, telesne symptomy, antikoncepce, plodnost |
| **Pravni zaklad** | **Cl. 9 odst. 2 pism. a) GDPR - vyslovny souhlas** |
| **Prijemci** | Supabase (DB uloziste) |
| **Prenosy do treti zeme** | USA (Supabase) - standardni smluvni dolozky |
| **Lhuta pro vymazani** | Do smazani uctu / odvolani souhlasu |
| **Technicka opatreni** | HTTPS, sifrovana DB, pristup pouze autentizovanym uzivatelum |

## 3. AI analyza cyklu

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Personalizovana AI analyza menstruacniho cyklu |
| **Kategorie subjektu** | Registrovani uzivatele (na vyzadani) |
| **Kategorie udaju** | **ZVLASTNI KATEGORIE** - anonymizovana data cyklu: delka cyklu, menstruace, nalady, symptomy, vek (bez emailu/jmena) |
| **Pravni zaklad** | **Cl. 9 odst. 2 pism. a) GDPR - vyslovny souhlas** |
| **Prijemci** | Anthropic PBC (AI model Claude) |
| **Prenosy do treti zeme** | USA (Anthropic) - standardni smluvni dolozky |
| **Lhuta pro vymazani** | 12 mesicu od vytvoreni analyzy |
| **Technicka opatreni** | Data odeslana bez emailu/jmena, HTTPS, API klic |

## 4. Sdileni s partnerem

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Dobrovolne sdileni vybranych dat cyklu s partnerem |
| **Kategorie subjektu** | Registrovani uzivatele a jejich partneri |
| **Kategorie udaju** | Sdileci kod, email partnera, vybrane udaje o cyklu dle nastaveni |
| **Pravni zaklad** | Cl. 6 odst. 1 pism. a) GDPR - souhlas |
| **Prijemci** | Supabase (DB), Google (SMTP pro emailove oznameni) |
| **Prenosy do treti zeme** | USA |
| **Lhuta pro vymazani** | Do odvolani / smazani uctu |
| **Technicka opatreni** | Unikatni 6znaky kod, uzivatel kontroluje rozsah sdileni |

## 5. Emailova komunikace

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Overovaci emaily, upozorneni na menstruaci, partnerske oznameni |
| **Kategorie subjektu** | Registrovani uzivatele |
| **Kategorie udaju** | Emailova adresa, jmeno, predikce menstruace |
| **Pravni zaklad** | Cl. 6 odst. 1 pism. b) GDPR - plneni smlouvy |
| **Prijemci** | Google LLC (Gmail SMTP) |
| **Prenosy do treti zeme** | USA (Google) |
| **Lhuta pro vymazani** | Do smazani uctu |
| **Technicka opatreni** | TLS sifrovani, autentizace SMTP |

## 6. Bezpecnost a ochrana

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Ochrana pred neautorizovanym pristupem, brute-force utoky |
| **Kategorie subjektu** | Vsichni navstevnici (prihlaseni i neprihlaseni) |
| **Kategorie udaju** | IP adresa, email, cas pokusu o prihlaseni |
| **Pravni zaklad** | Cl. 6 odst. 1 pism. f) GDPR - opravneny zajem |
| **Prijemci** | Supabase (DB), Render (hosting) |
| **Prenosy do treti zeme** | USA |
| **Lhuta pro vymazani** | 24 hodin (automaticky cleanup) |
| **Technicka opatreni** | Rate limiting (10/15min), IP logging |

## 7. Zaznamy souhlasu (GDPR compliance)

| Polozka | Popis |
|---------|-------|
| **Ucel zpracovani** | Prokazani platneho souhlasu dle GDPR |
| **Kategorie subjektu** | Registrovani uzivatele |
| **Kategorie udaju** | Typ souhlasu, stav, IP adresa, casove razitko |
| **Pravni zaklad** | Cl. 6 odst. 1 pism. c) GDPR - pravni povinnost |
| **Prijemci** | Supabase (DB) |
| **Prenosy do treti zeme** | USA (Supabase) |
| **Lhuta pro vymazani** | 5 let od udeleni souhlasu |
| **Technicka opatreni** | Immutable zaznamy, casova razitka |

---

## Prehled technickych a organizacnich opatreni

| Opatreni | Implementace |
|----------|-------------|
| Sifrovani pri prenosu | HTTPS/TLS (force redirect) |
| Sifrovani hesel | bcrypt, 12 kol |
| Pristupova kontrola | Session autentizace, requireAuth middleware |
| CSRF ochrana | Tokenova ochrana na vsech POST/PUT/DELETE |
| Rate limiting | 10 pokusu / 15 minut na prihlaseni |
| HttpOnly cookies | Ano |
| Secure cookies | Ano (produkce) |
| SameSite cookies | Lax |
| Email verifikace | 6mistny kod, platnost 15 minut |
| Pravo na vymazani | Endpoint /api/gdpr/delete-account |
| Pravo na export | Endpoint /api/gdpr/export-data |
| Automaticky cleanup | Endpoint /api/cleanup (login attempts 24h) |
