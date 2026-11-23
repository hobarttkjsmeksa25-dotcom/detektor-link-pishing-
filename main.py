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
    <p>{{ hasil.catatan }}</p>
  </div>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    hasil = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            hasil = {
                "url": url_input,
                "catatan": "Tahap 1 aktif: input URL berhasil diterima server."
            }
    return render_template_string(HTML_TEMPLATE, hasil=hasil, url=url_input)


if __name__ == "__main__":
    app.run(debug=True)