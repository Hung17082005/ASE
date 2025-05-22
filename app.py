from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from io import BytesIO

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["file"]
        key = request.form["key"].encode("utf-8")
        mode = request.form["mode"]

        if len(key) != 16:
            return "Khóa AES phải đúng 16 ký tự", 400

        data = file.read()
        iv = b"1234567890987654" 
        if len(iv) != 16:
            return "IV phải đúng 16 ký tự", 400
        cipher = AES.new(key, AES.MODE_CBC, iv)

        if mode == "encrypt":
            encrypted = cipher.encrypt(pad(data, AES.block_size))
            output = BytesIO(encrypted)
            out_filename = "encrypted.aes"
        else:
            try:
                decrypted = unpad(cipher.decrypt(data), AES.block_size)
            except ValueError:
                return "Giải mã thất bại: sai khóa hoặc dữ liệu", 400
            output = BytesIO(decrypted)
            out_filename = "decrypted_" + file.filename

        output.seek(0)
        return send_file(output, as_attachment=True, download_name=out_filename)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
