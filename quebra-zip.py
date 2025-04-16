import os
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from zipfile import ZipFile, BadZipFile
import subprocess
from concurrent.futures import ThreadPoolExecutor

SUPPORTED_ZIPFILE_METHODS = {0, 8}  # Sem compressão ou Deflate

def detect_encryption_and_compression(zip_file_path):
    try:
        with ZipFile(zip_file_path, 'r') as zip_file:
            for info in zip_file.infolist():
                is_encrypted = info.flag_bits & 0x1
                method = info.compress_type

                print(f"Arquivo: {info.filename}, Método de compressão: {method}, Encriptado: {is_encrypted}")

                if is_encrypted:
                    if method not in SUPPORTED_ZIPFILE_METHODS:
                        return "AES"
                    return "ZipCrypto"
        return "Nenhuma"
    except BadZipFile:
        return None
    except RuntimeError as e:
        if "encrypted" in str(e).lower():
            return "AES"
        return None

def test_zipcrypto_password(zip_file_path, password, result_queue):
    try:
        with ZipFile(zip_file_path, 'r') as zip_file:
            zip_file.extractall(pwd=password.encode('utf-8'))
            result_queue.put(password)
    except Exception as e:
        print(f"Erro ao testar senha ZipCrypto: {e}")

def test_aes_password(zip_file_path, password, result_queue):
    try:
        seven_zip_path = r"C:\Program Files\7-Zip\7z.exe"
        command = [seven_zip_path, 't', zip_file_path, f'-p{password}']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            result_queue.put(password)
    except Exception as e:
        print(f"Erro ao executar o comando 7z: {e}")

def clean_wordlist(wordlist_path):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors='ignore') as file:
            lines = file.read().splitlines()

        clean_lines = [line.strip() for line in lines if line.strip()]
        cleaned_wordlist_path = wordlist_path.replace(".txt", "_clean.txt")
        with open(cleaned_wordlist_path, "w", encoding="utf-8") as file:
            file.write("\n".join(clean_lines))
        return cleaned_wordlist_path
    except Exception as e:
        print(f"Erro ao limpar a wordlist: {e}")
        return None

def process_passwords(zip_file_path, wordlist_path, encryption_type, progress_var, log_text, stop_event):
    cleaned_wordlist_path = clean_wordlist(wordlist_path)
    if not cleaned_wordlist_path:
        messagebox.showerror("Erro", "Falha ao limpar a wordlist.")
        return

    result_queue = queue.Queue()
    with open(cleaned_wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
        passwords = file.read().splitlines()

    total_passwords = len(passwords)
    processed_passwords = 0

    test_function = test_zipcrypto_password if encryption_type == "ZipCrypto" else test_aes_password

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for password in passwords:
            if stop_event.is_set():
                break
            log_text.insert(tk.END, f"Testando: {password}\n")
            log_text.see(tk.END)
            futures.append(executor.submit(test_function, zip_file_path, password, result_queue))

        for future in futures:
            if stop_event.is_set():
                break
            future.result()
            processed_passwords += 1
            progress = (processed_passwords / total_passwords) * 100
            progress_var.set(progress)

    if not result_queue.empty():
        found_password = result_queue.get()
        log_text.insert(tk.END, f"Senha encontrada: {found_password}\n")
        messagebox.showinfo("Sucesso", f"Senha encontrada: {found_password}")
    else:
        log_text.insert(tk.END, "Senha não encontrada.\n")
        messagebox.showwarning("Falha", "Senha não encontrada.")

class ZipCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Quebra Zip")
        self.stop_event = threading.Event()

        self.zip_file_path = tk.StringVar()
        self.wordlist_path = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.encryption_type = tk.StringVar()
        
        button_style = {
            "bg": "#60B5FF",  # Cor de fundo (verde)
            "fg": "white",    # Cor do texto (branco)
            "font": ("Arial", 10),  # Fonte
            "width": 15,      # Largura do botão
            "height": 1,      # Altura do botão
            "bd": 3,          # Largura da borda
            "relief": "sunken"  # Estilo da borda (raised, flat, sunken, etc.)
        }

        # Layout
        tk.Label(root, text="Arquivo ZIP:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(root, textvariable=self.zip_file_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root,button_style, text="Selecionar", command=self.select_zip_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(root, text="Wordlist:").grid(row=1, column=0, padx=5, pady=5)
        tk.Entry(root, textvariable=self.wordlist_path, width=50).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(root,button_style, text="Selecionar", command=self.select_wordlist).grid(row=1, column=2, padx=5, pady=5)

        tk.Button(root,button_style, text="Iniciar", command=self.start_cracking).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(root,button_style, text="Pausar", command=self.pause_cracking).grid(row=2, column=1, padx=5, pady=5)
        tk.Button(root,button_style, text="Cancelar", command=self.cancel_cracking).grid(row=2, column=2, padx=5, pady=5)

        # Label para mostrar o tipo de criptografia detectado
        self.encryption_label = tk.Label(root, textvariable=self.encryption_type, fg="blue", font=("Arial", 10, "bold"))
        self.encryption_label.grid(row=3, column=0, columnspan=3, pady=5)

        self.progress_bar = ttk.Progressbar(root, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

        self.log_text = tk.Text(root, height=10, width=80)
        self.log_text.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

    def select_zip_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Arquivos ZIP", "*.zip")])
        if file_path:
            self.zip_file_path.set(file_path)

    def select_wordlist(self):
        file_path = filedialog.askopenfilename(filetypes=[("Arquivos de Texto", "*.txt")])
        if file_path:
            self.wordlist_path.set(file_path)

    def start_cracking(self):
        zip_file = self.zip_file_path.get()
        wordlist = self.wordlist_path.get()

        if not zip_file or not wordlist:
            messagebox.showerror("Erro", "Selecione o arquivo ZIP e a wordlist.")
            return

        encryption_type = detect_encryption_and_compression(zip_file)
        if not encryption_type:
            messagebox.showerror("Erro", "Arquivo ZIP inválido ou corrompido.")
            return

        # Atualiza a label na interface com o tipo detectado
        self.encryption_type.set(f"Tipo de criptografia detectado: {encryption_type}")
        print(f"Tipo de criptografia detectado: {encryption_type}")

        if encryption_type == "Nenhuma":
            messagebox.showinfo("Info", "O arquivo ZIP não está criptografado.")
            return

        self.stop_event.clear()
        threading.Thread(
            target=process_passwords,
            args=(zip_file, wordlist, encryption_type, self.progress_var, self.log_text, self.stop_event)
        ).start()

    def pause_cracking(self):
        self.stop_event.set()

    def cancel_cracking(self):
        self.stop_event.set()
        self.progress_var.set(0)
        self.log_text.delete(1.0, tk.END)
        self.encryption_type.set("")

if __name__ == "__main__":
    root = tb.Window(themename="darkly")  # Outros temas: 'cyborg', 'superhero', 'solar', 'darkly'
    app = ZipCrackerApp(root)
    root.mainloop()
