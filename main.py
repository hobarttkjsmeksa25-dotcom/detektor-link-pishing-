from flask import Flask, request, render_template
from detector import cek_phishing

app = Flask("phishguard")


@app.route("/", methods=["GET", "POST"])
def index():
    hasil = None
    error = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if not url_input:
            error = "Silakan masukkan link terlebih dahulu sebelum menekan Cek Link."
        else:
            hasil = cek_phishing(url_input)
    return render_template("index.html", hasil=hasil, error=error, url=url_input)


if __name__ == "__main__":
    app.run(debug=True)