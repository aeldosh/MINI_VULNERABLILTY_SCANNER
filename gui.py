import tkinter as tk
from tkinter import ttk
from scanner import run_scan
from pdf_report import generate_pdf_report
import threading
import time

# ---------------- GUI FUNCTIONS ---------------- #

def start_scan():
    target = target_entry.get().strip()
    if not target:
        return

    output.delete("1.0", tk.END)
    output.insert(tk.END, "[*] Initializing scan...\n")

    progress_bar["value"] = 0
    progress_label.config(text="Starting scan...")

    scan_thread = threading.Thread(target=run_scan_thread, args=(target,))
    scan_thread.start()


def run_scan_thread(target):
    progress_steps = 20

    for i in range(progress_steps):
        time.sleep(0.1)
        progress_bar["value"] += 100 / progress_steps
        progress_label.config(text=f"Scanning ports... {int(progress_bar['value'])}%")
        root.update_idletasks()

    services = run_scan(target)

    output.insert(tk.END, "\n[+] Scan Results:\n")
    for port, service in services.items():
        output.insert(tk.END, f"[OPEN] Port {port} → {service}\n")

    report_file = generate_pdf_report(target, list(services.keys()))
    output.insert(tk.END, f"\n[✔] Report saved: {report_file}\n")

    progress_label.config(text="Scan completed ✔")
    progress_bar["value"] = 100


# ---------------- GUI WINDOW ---------------- #

root = tk.Tk()
root.title("Mini Vulnerability Scanner")
root.geometry("720x520")
root.configure(bg="#0f0f0f")

# ---------------- STYLES ---------------- #

style = ttk.Style()
style.theme_use("default")

style.configure(
    "TProgressbar",
    thickness=18,
    troughcolor="#1a1a1a",
    background="#00ff88"
)

FONT_TITLE = ("Consolas", 20, "bold")
FONT_TEXT = ("Consolas", 11)

# ---------------- TITLE ---------------- #

title = tk.Label(
    root,
    text="🛡 Mini Vulnerability Scanner",
    font=FONT_TITLE,
    fg="#00ff88",
    bg="#0f0f0f"
)
title.pack(pady=15)

# ---------------- INPUT ---------------- #

target_entry = tk.Entry(
    root,
    font=("Consolas", 13),
    bg="#1e1e1e",
    fg="#00ff88",
    insertbackground="#00ff88",
    relief="flat",
    width=35
)
target_entry.pack(pady=10)
target_entry.insert(0, "scanme.nmap.org")

# ---------------- BUTTON ---------------- #

scan_button = tk.Button(
    root,
    text="▶ START SCAN",
    font=("Consolas", 12, "bold"),
    bg="#00ff88",
    fg="#000000",
    activebackground="#00cc6a",
    relief="flat",
    command=start_scan
)
scan_button.pack(pady=10)

# ---------------- PROGRESS ---------------- #

progress_label = tk.Label(
    root,
    text="Waiting...",
    font=FONT_TEXT,
    fg="#00ff88",
    bg="#0f0f0f"
)
progress_label.pack()

progress_bar = ttk.Progressbar(
    root,
    orient="horizontal",
    length=500,
    mode="determinate"
)
progress_bar.pack(pady=10)

# ---------------- OUTPUT ---------------- #

output = tk.Text(
    root,
    bg="#1a1a1a",
    fg="#00ff88",
    insertbackground="#00ff88",
    font=FONT_TEXT,
    relief="flat",
    height=12
)
output.pack(padx=15, pady=15, fill="both", expand=True)

root.mainloop()
