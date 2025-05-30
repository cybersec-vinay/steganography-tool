import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, colorchooser, font
from tkinterdnd2 import DND_FILES, TkinterDnD
from PIL import Image, ImageTk
from stegano import lsb
import zlib
import base64
import os
from datetime import datetime

# --- Utility Functions ---
def encrypt_message(message, password):
    combined = (password + '::' + message).encode('utf-8')
    
    return base64.b64encode(combined).decode('utf-8')

def decrypt_message(encoded_message, password):
    try:
        decoded = base64.b64decode(encoded_message.encode('utf-8')).decode('utf-8')
        parts = decoded.split('::', 1)
        if len(parts) == 2 and parts[0] == password:
            return parts[1]
        else:
            raise ValueError("Incorrect password or corrupted message.")
    except Exception as e:
        raise ValueError("Decoding failed. Possibly wrong password or data corruption.")

# --- App Setup ---
app = TkinterDnD.Tk()
app.title("🔐 Steganography Tool")
app.geometry("850x650")
app.configure(bg="#f9f9f9")

selected_image = None
photo = None

# --- Functions ---
def browse_image():
    global selected_image, photo
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if file_path:
        selected_image = file_path
        img = Image.open(file_path).resize((250, 250))
        photo = ImageTk.PhotoImage(img)
        image_label.config(image=photo)

def drag_drop_image(event):
    global selected_image, photo
    file_path = event.data
    if os.path.isfile(file_path):
        selected_image = file_path
        img = Image.open(file_path).resize((250, 250))
        photo = ImageTk.PhotoImage(img)
        image_label.config(image=photo)

def encode_message():
    if not selected_image:
        messagebox.showerror("Error", "Please select an image.")
        return
    message = message_box.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Please enter a message.")
        return
    password = simpledialog.askstring("Password", "Enter password for encryption:", show='*')
    if not password:
        return
    if compress_var.get():
        message = zlib.compress(message.encode("utf-8"))
        message = base64.b64encode(message).decode("utf-8")
    encrypted = encrypt_message(message, password)
    output_path = filedialog.asksaveasfilename(defaultextension=".png")
    if output_path:
        try:
            lsb.hide(selected_image, encrypted).save(output_path)
            messagebox.showinfo("Success", "Message encoded and image saved!")
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")

def decode_message():
    if not selected_image:
        messagebox.showerror("Error", "Please select an image to decode.")
        return
    password = simpledialog.askstring("Password", "Enter password to decrypt:", show='*')
    if not password:
        return
    try:
        hidden_message = lsb.reveal(selected_image)
        if not hidden_message:
            raise ValueError("No hidden message found.")
        decrypted = decrypt_message(hidden_message, password)
        if decompress_var.get():
            decrypted = base64.b64decode(decrypted)
            decrypted = zlib.decompress(decrypted).decode("utf-8")
        message_box.delete("1.0", tk.END)
        message_box.insert(tk.END, decrypted)
        preview_label.config(text=f"📝 Message Preview:\n{decrypted[:100]}...")
        log_output(decrypted)
        messagebox.showinfo("Decoded", "Message successfully decoded.")
    except Exception as e:
        messagebox.showerror("Error", f"Decoding failed: {e}")

def log_output(message):
    log_file_path = os.path.abspath("decoded_log.txt")
    with open(log_file_path, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")
    messagebox.showinfo("Log Saved", f"Decoded message has been saved to:\n\n{log_file_path}")


def change_font():
    top = tk.Toplevel(app)
    top.title("Choose Font")
    tk.Label(top, text="Font Family:").pack()
    font_family = tk.StringVar(top)
    font_family.set("Arial")
    families = sorted(set(font.families()))
    family_menu = tk.OptionMenu(top, font_family, *families)
    family_menu.pack()

    tk.Label(top, text="Size:").pack()
    size_var = tk.IntVar(top)
    size_var.set(12)
    size_entry = tk.Entry(top, textvariable=size_var)
    size_entry.pack()

    def apply_font():
        message_box.config(font=(font_family.get(), size_var.get()))
        top.destroy()

    tk.Button(top, text="Apply", command=apply_font).pack()

def change_color():
    color = colorchooser.askcolor()[1]
    if color:
        message_box.config(fg=color)

# --- GUI Layout ---
title_label = tk.Label(app, text="🛡️ Steganography Encoder/Decoder", font=("Helvetica", 20, "bold"), bg="#f9f9f9")
title_label.pack(pady=10)

image_label = tk.Label(app, text="[Drop or Browse Image]", width=250, height=250, bg="white", relief="groove")
image_label.pack(pady=10)
image_label.drop_target_register(DND_FILES)
image_label.dnd_bind('<<Drop>>', drag_drop_image)

browse_btn = tk.Button(app, text="📁 Browse Image", command=browse_image)
browse_btn.pack(pady=5)

message_box = tk.Text(app, height=8, wrap=tk.WORD, font=("Arial", 12))
message_box.pack(pady=10, padx=20, fill=tk.X)

preview_label = tk.Label(app, text="📝 Message Preview: (After Decode)", bg="#f9f9f9", anchor="w", justify="left")
preview_label.pack(padx=20, fill=tk.X)

toolbar = tk.Frame(app, bg="#f9f9f9")
toolbar.pack(pady=5)

font_btn = tk.Button(toolbar, text="🎨 Font", command=change_font)
font_btn.pack(side=tk.LEFT, padx=5)

color_btn = tk.Button(toolbar, text="🌈 Text Color", command=change_color)
color_btn.pack(side=tk.LEFT, padx=5)

compress_var = tk.BooleanVar()
compress_check = tk.Checkbutton(toolbar, text="Compress", variable=compress_var, bg="#f9f9f9")
compress_check.pack(side=tk.LEFT, padx=5)

decompress_var = tk.BooleanVar()
decompress_check = tk.Checkbutton(toolbar, text="Decompress", variable=decompress_var, bg="#f9f9f9")
decompress_check.pack(side=tk.LEFT, padx=5)

btn_frame = tk.Frame(app, bg="#f9f9f9")
btn_frame.pack(pady=20)

encode_btn = tk.Button(btn_frame, text="🔐 Encode Message", command=encode_message, bg="#4CAF50", fg="white", padx=10)
encode_btn.grid(row=0, column=0, padx=10)

decode_btn = tk.Button(btn_frame, text="🔓 Decode Message", command=decode_message, bg="#2196F3", fg="white", padx=10)
decode_btn.grid(row=0, column=1, padx=10)

# --- Run ---
app.mainloop()
