import re
from urllib.parse import urlparse
from flask import Flask, request, render_template_string

app = Flask("phishguard")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <title>PhishGuard - Detektor Link Phishing</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
    input[type="text"] { width: 75%; padding: 8px; }
    button { padding: 8px 14px; cursor: pointer; }
    .box { margin-top: 20px; padding: 14px; border: 1px solid #ccc; border-radius: 6px; }
  </style>
</head>
<body>
  <h2>Detektor Link Phishing</h2>
  <form method="POST">
    <input type="text" name="url" placeholder="Masukkan link yang ingin dicek..." value="{{ url or '' }}" required>
    <button type="submit">Cek Link</button>
  </form>

  {% if hasil %}
  <div class="box">
    <strong>URL Diperiksa: {{ hasil.url }}</strong>
    <p>Skor Sementara: {{ hasil.skor }}</p>
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


def analisis_struktur_dasar(raw_url: str) -> dict:
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

    if not indikator:
        indikator.append("Tidak ada indikasi pada pemeriksaan struktur dasar.")

    return {"url": url, "skor": skor, "indikator": indikator}


@app.route("/", methods=["GET", "POST"])
def index():
    hasil = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            hasil = analisis_struktur_dasar(url_input)
    return render_template_string(HTML_TEMPLATE, hasil=hasil, url=url_input)


if __name__ == "__main__":
    app.run(debug=True)