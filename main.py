import re
from urllib.parse import urlparse
from flask import Flask, request, render_template_string

app = Flask("phishguard")

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

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <title>PhishGuard - Detektor Link Phishing</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
    input[type="text"] { width: 70%; padding: 8px; }
    button, .btn-reset { padding: 8px 12px; cursor: pointer; text-decoration: none; font-size: 14px; }
    .btn-reset { border: 1px solid #bbb; color: #333; border-radius: 3px; margin-left: 4px; }
    .box { margin-top: 20px; padding: 14px; border: 1px solid #ccc; border-radius: 6px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 13px; font-weight: bold; }
    .badge-aman { background: #e6f4ea; color: #137333; }
    .badge-waspada { background: #fef7e0; color: #b06000; }
    .badge-tinggi { background: #fce8e6; color: #c5221f; }
    .meta { color: #555; font-size: 13px; margin-top: 4px; }
  </style>
</head>
<body>
  <h2>Detektor Link Phishing</h2>
  <form method="POST">
    <input type="text" name="url" placeholder="Masukkan link yang ingin dicek..." value="{{ url or '' }}" required>
    <button type="submit">Cek Link</button>
    <a class="btn-reset" href="/">Reset</a>
  </form>

  {% if hasil %}
  <div class="box">
    <strong>URL Diperiksa: {{ hasil.url }}</strong>
    <p>
      Status: <span class="badge {{ hasil.badge_class }}">{{ hasil.status }}</span>
      &nbsp;|&nbsp; Skor: <strong>{{ hasil.skor }}</strong>
    </p>
    <div class="meta">Jumlah temuan indikator: {{ hasil.jumlah_indikator }}</div>
    <ul>
      {% for item in hasil.indikator %}
      <li>{{ item }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}
</body>
</html>
"""


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

    skor = 0
    indikator = []

    if parsed.scheme != "https":
        skor += 20
        indikator.append("Tidak menggunakan protokol HTTPS.")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        skor += 35
        indikator.append("Menggunakan alamat IP langsung sebagai host.")

    if "@" in url:
        skor += 30
        indikator.append("Mengandung karakter '@' untuk mengaburkan tujuan domain.")

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


@app.route("/", methods=["GET", "POST"])
def index():
    hasil = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            hasil = cek_phishing(url_input)
    return render_template_string(HTML_TEMPLATE, hasil=hasil, url=url_input)


if __name__ == "__main__":
    app.run(debug=True)