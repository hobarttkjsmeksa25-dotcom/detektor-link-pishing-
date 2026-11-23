import re
from urllib.parse import urlparse

TLD_BERISIKO = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".zip"}

KATA_KUNCI_PHISHING = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "signin",
    "akun",
    "verifikasi",
    "blokir",
    "hadiah",
    "klaim",
    "sandi",
}


def normalisasi_url(raw_url: str) -> str:
    bersih = raw_url.strip()
    if not bersih.startswith(("http://", "https://")):
        return "http://" + bersih
    return bersih


def klasifikasi_risiko(skor: int) -> tuple[str, str]:
    if skor >= 50:
        return "Berisiko Tinggi", "badge-tinggi"
    if skor >= 25:
        return "Waspada / Mencurigakan", "badge-waspada"
    return "Relatif Aman", "badge-aman"


def cek_phishing(raw_url: str) -> dict:
    url = normalisasi_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))

    skor = 0
    indikator = []

    if parsed.scheme != "https":
        skor += 20
        indikator.append("Tidak menggunakan protokol HTTPS.")

    if is_ip:
        skor += 35
        indikator.append("Menggunakan alamat IP langsung sebagai host.")

    if "@" in url:
        skor += 30
        indikator.append("Mengandung karakter '@' untuk mengaburkan tujuan domain.")

    if not is_ip and host.count(".") >= 3:
        skor += 15
        indikator.append("Memiliki banyak subdomain berlapis pada nama host.")

    if host.count("-") >= 2:
        skor += 20
        indikator.append("Nama domain memiliki banyak tanda hubung ('-').")

    if len(url) > 75:
        skor += 15
        indikator.append("Panjang URL melebihi 75 karakter.")

    if any(host.endswith(tld) for tld in TLD_BERISIKO):
        skor += 25
        indikator.append("Menggunakan ekstensi domain (TLD) yang sering muncul pada link mencurigakan.")

    jalur_dan_query = f"{parsed.path} {parsed.query}".lower()
    kata_ditemukan = [
        k for k in KATA_KUNCI_PHISHING if re.search(rf"\b{re.escape(k)}\b", jalur_dan_query)
    ]
    if kata_ditemukan:
        skor += 15
        indikator.append(
            f"Mengandung kata kunci pancingan pada URL: {', '.join(sorted(kata_ditemukan))}."
        )

    jumlah_indikator = len(indikator)
    if not indikator:
        indikator.append("Tidak ditemukan pola mencurigakan pada aturan heuristik saat ini.")

    status, badge_class = klasifikasi_risiko(skor)

    return {
        "url": url,
        "skor": skor,
        "status": status,
        "badge_class": badge_class,
        "jumlah_indikator": jumlah_indikator,
        "indikator": indikator,
    }