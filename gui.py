import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scanner import run_scan, resolve_target
from pdf_report import generate_pdf_report
import time

# ---------------- THEME & COLORS ---------------- #
COLORS = {
    "bg": "#0a0a0f",
    "panel": "#12121a",
    "card": "#1a1a2e",
    "text": "#ffffff",
    "text_muted": "#8888aa",
    "accent": "#00ff88",
    "critical": "#ff4444",
    "high": "#ff8c00",
    "medium": "#ffd700",
    "low": "#00ff88",
    "border": "#2a2a3e"
}

FONT_TITLE = ("Consolas", 18, "bold")
FONT_SUBTITLE = ("Consolas", 12, "bold")
FONT_TEXT = ("Consolas", 10)

def get_risk_color(risk):
    return COLORS.get(risk.lower(), COLORS['text'])

# ---------------- GUI ---------------- #
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini Vulnerability Scanner - Advanced Edition")
        self.root.geometry("900x650")
        self.root.configure(bg=COLORS["bg"])
        
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        
        # Notebook (Tabs)
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["panel"], foreground=COLORS["text"],
                        padding=[15, 5], font=FONT_TEXT, borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", COLORS["card"])], 
                  foreground=[("selected", COLORS["accent"])])
                  
        # Frame
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("Card.TFrame", background=COLORS["card"])
        
        # Progressbar
        style.configure("TProgressbar", thickness=15, troughcolor=COLORS["panel"],
                        background=COLORS["accent"], borderwidth=0)
                        
        # Treeview
        style.configure("Treeview", background=COLORS["panel"], fieldbackground=COLORS["panel"],
                        foreground=COLORS["text"], rowheight=30, borderwidth=0, font=FONT_TEXT)
        style.map("Treeview", background=[("selected", COLORS["card"])])
        style.configure("Treeview.Heading", background=COLORS["card"], foreground=COLORS["text"],
                        font=FONT_SUBTITLE, borderwidth=0)

    def create_widgets(self):
        # ── Header ──
        header = tk.Frame(self.root, bg=COLORS["bg"], pady=15)
        header.pack(fill=tk.X)
        
        title = tk.Label(header, text="🛡 Adv. Vulnerability Scanner", font=FONT_TITLE,
                         fg=COLORS["accent"], bg=COLORS["bg"])
        title.pack(side=tk.LEFT, padx=20)
        
        self.btn_scan = tk.Button(header, text="▶ START SCAN", font=FONT_SUBTITLE, 
                                  bg=COLORS["accent"], fg="#000000", bd=0, padx=15, pady=5,
                                  command=self.start_scan, cursor="hand2")
        self.btn_scan.pack(side=tk.RIGHT, padx=20)
        
        self.entry_target = tk.Entry(header, font=("Consolas", 12), bg=COLORS["panel"],
                                     fg=COLORS["accent"], insertbackground=COLORS["accent"],
                                     bd=1, relief="ridge", width=30)
        self.entry_target.pack(side=tk.RIGHT, padx=10)
        self.entry_target.insert(0, "scanme.nmap.org")
        
        # ── Tabs ──
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.tab_dash = ttk.Frame(self.notebook, style="TFrame")
        self.tab_ports = ttk.Frame(self.notebook, style="TFrame")
        self.tab_web = ttk.Frame(self.notebook, style="TFrame")
        self.tab_log = ttk.Frame(self.notebook, style="TFrame")
        
        self.notebook.add(self.tab_dash, text="Dashboard")
        self.notebook.add(self.tab_ports, text="Port Scan & Vulns")
        self.notebook.add(self.tab_web, text="Web Analysis (SSL/Headers)")
        self.notebook.add(self.tab_log, text="Live Log")
        
        self.setup_dash_tab()
        self.setup_ports_tab()
        self.setup_web_tab()
        self.setup_log_tab()
        
        # ── Footer ──
        footer = tk.Frame(self.root, bg=COLORS["bg"], pady=10)
        footer.pack(fill=tk.X, padx=20)
        
        self.lbl_status = tk.Label(footer, text="Ready", font=FONT_TEXT, fg=COLORS["text"], bg=COLORS["bg"])
        self.lbl_status.pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(footer, mode="determinate", length=400)
        self.progress.pack(side=tk.RIGHT)
        
    def setup_dash_tab(self):
        # Stats summary boxes
        container = tk.Frame(self.tab_dash, bg=COLORS["bg"], pady=20)
        container.pack(fill=tk.BOTH, expand=True)
        
        self.lbl_ip = tk.Label(container, text="Target IP: -", font=FONT_SUBTITLE, fg=COLORS["text_muted"], bg=COLORS["bg"])
        self.lbl_ip.pack(pady=10)
        
        cards_frame = tk.Frame(container, bg=COLORS["bg"])
        cards_frame.pack(pady=20)
        
        self.stat_vars = {}
        for title, col in [("Critical", COLORS["critical"]), ("High", COLORS["high"]), 
                           ("Medium", COLORS["medium"]), ("Low", COLORS["low"]), ("Info", "#2196f3")]:
            card = tk.Frame(cards_frame, bg=COLORS["card"], padx=20, pady=15, bd=1, relief="ridge")
            card.pack(side=tk.LEFT, padx=10)
            tk.Label(card, text=title, font=FONT_TEXT, fg=COLORS["text"], bg=COLORS["card"]).pack()
            val_lbl = tk.Label(card, text="0", font=FONT_TITLE, fg=col, bg=COLORS["card"])
            val_lbl.pack(pady=5)
            self.stat_vars[title] = val_lbl

    def setup_ports_tab(self):
        columns = ("port", "service", "severity", "banner")
        self.tree_ports = ttk.Treeview(self.tab_ports, columns=columns, show="headings")
        
        self.tree_ports.heading("port", text="Port")
        self.tree_ports.column("port", width=80, anchor=tk.CENTER)
        
        self.tree_ports.heading("service", text="Service")
        self.tree_ports.column("service", width=120)
        
        self.tree_ports.heading("severity", text="Risk Severity")
        self.tree_ports.column("severity", width=120, anchor=tk.CENTER)
        
        self.tree_ports.heading("banner", text="Banner / Details")
        self.tree_ports.column("banner", width=400)
        
        self.tree_ports.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Tags for colored text
        self.tree_ports.tag_configure("Critical", foreground=COLORS["critical"])
        self.tree_ports.tag_configure("High", foreground=COLORS["high"])
        self.tree_ports.tag_configure("Medium", foreground=COLORS["medium"])
        self.tree_ports.tag_configure("Low", foreground=COLORS["low"])
        
    def setup_web_tab(self):
        # Two pane setup
        self.pane_ssl = tk.LabelFrame(self.tab_web, text="SSL/TLS Certificate", font=FONT_SUBTITLE, 
                                      bg=COLORS["bg"], fg=COLORS["accent"], padx=10, pady=10)
        self.pane_ssl.pack(fill=tk.X, pady=10)
        self.ssl_text = tk.Label(self.pane_ssl, text="No SSL data.", justify=tk.LEFT, font=FONT_TEXT, bg=COLORS["bg"], fg=COLORS["text"])
        self.ssl_text.pack(anchor=tk.W)
        
        self.pane_headers = tk.LabelFrame(self.tab_web, text="Security Headers", font=FONT_SUBTITLE, 
                                          bg=COLORS["bg"], fg=COLORS["accent"], padx=10, pady=10)
        self.pane_headers.pack(fill=tk.BOTH, expand=True, pady=10)
        
        columns = ("header", "status")
        self.tree_headers = ttk.Treeview(self.pane_headers, columns=columns, show="headings")
        self.tree_headers.heading("header", text="Header")
        self.tree_headers.column("header", width=200)
        self.tree_headers.heading("status", text="Status")
        self.tree_headers.column("status", width=500)
        self.tree_headers.pack(fill=tk.BOTH, expand=True)
        
        self.tree_headers.tag_configure("Missing", foreground=COLORS["critical"])
        self.tree_headers.tag_configure("Present", foreground=COLORS["low"])

    def setup_log_tab(self):
        self.txt_log = scrolledtext.ScrolledText(self.tab_log, bg=COLORS["panel"], fg=COLORS["low"], 
                                                 font=FONT_TEXT, insertbackground=COLORS["low"],
                                                 bd=0, relief="flat", padx=10, pady=10)
        self.txt_log.pack(fill=tk.BOTH, expand=True)
        
    def log(self, message):
        self.root.after(0, lambda: self._log(message))
        
    def _log(self, message):
        self.txt_log.insert(tk.END, message + "\n")
        self.txt_log.see(tk.END)
        
    def update_progress(self, percent, text):
        self.root.after(0, lambda: self._update_progress(percent, text))
        
    def _update_progress(self, percent, text):
        self.progress["value"] = percent
        self.lbl_status.config(text=text)
        
    def start_scan(self):
        target = self.entry_target.get().strip()
        if not target: return
        
        self.btn_scan.config(state="disabled")
        self.txt_log.delete(1.0, tk.END)
        for item in self.tree_ports.get_children(): self.tree_ports.delete(item)
        for item in self.tree_headers.get_children(): self.tree_headers.delete(item)
        
        for k in self.stat_vars: self.stat_vars[k].config(text="0")
        self.ssl_text.config(text="Scanning...")
        
        self.notebook.select(3) # Switch to log
        
        self.log(f"[*] Starting advanced security scan on {target}")
        
        # Run in thread
        threading.Thread(target=self.run_scan_thread, args=(target,), daemon=True).start()

    def run_scan_thread(self, target):
        self.update_progress(0, "Resolving DNS...")
        
        start_time = time.time()
        
        # Scan Progress proxy
        def on_prog(pct, total):
            self.update_progress(pct, f"Scanning operations in progress... {pct}%")
            
        try:
            result = run_scan(target, progress_callback=on_prog)
            
            elapsed = time.time() - start_time
            self.log(f"[+] Scan completed in {elapsed:.1f} seconds")
            
            self.root.after(0, lambda: self.render_results(result))
            
            # PDF Gen
            self.update_progress(95, "Generating PDF Report...")
            pdf_path = generate_pdf_report(result)
            self.log(f"[✔] Report saved to: {pdf_path}")
            
            self.update_progress(100, f"Scan Complete - Saved to {pdf_path}")
            
        except Exception as e:
             import traceback
             self.log(f"[!] Error during scan: {str(e)}")
             self.log(traceback.format_exc())
             self.update_progress(0, "Scan Failed")
             
        finally:
             self.root.after(0, lambda: self.btn_scan.config(state="normal"))

    def render_results(self, result):
        # Dash
        self.lbl_ip.config(text=f"Target IP: {result.ip}")
        if result.dns_info.get("reverse_dns"):
             self.lbl_ip.config(text=self.lbl_ip.cget("text") + f" | rDNS: {result.dns_info['reverse_dns']}")
             
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        
        # Ports
        for port, p_data in result.ports.items():
            sev = p_data["risk"]["severity"]
            if sev in counts: counts[sev] += 1
            
            self.tree_ports.insert("", tk.END, values=(
                port, p_data["service"], sev, p_data.get("banner") or "No banner"
            ), tags=(sev,))
            self.log(f"[+] Port {port} ({p_data['service']}) - {sev}")
            
        for k in self.stat_vars:
            self.stat_vars[k].config(text=str(counts[k]))
            
        # SSL
        if result.ssl:
            ssl_str = f"Issuer: {result.ssl.get('issuer')}\n"
            ssl_str += f"Subject: {result.ssl.get('subject')}\n"
            ssl_str += f"Validity: {result.ssl.get('valid_from')} to {result.ssl.get('valid_to')}\n"
            days = result.ssl.get('days_until_expiry', 0)
            ssl_str += f"Status: {'VALID' if result.ssl.get('is_valid') else 'EXPIRED'} ({days} days left)"
            self.ssl_text.config(text=ssl_str)
        else:
            self.ssl_text.config(text="No SSL/TLS certificate detected.")
            
        # Headers
        if result.headers:
            self.pane_headers.config(text=f"Security Headers (Grade: {result.headers.get('grade', 'N/A')})")
            for h in result.headers.get("present", []):
                self.tree_headers.insert("", tk.END, values=(h, "Present / Secure"), tags=("Present",))
            for m in result.headers.get("missing", []):
                self.tree_headers.insert("", tk.END, values=(m["header"], m["warning"]), tags=("Missing",))
                
        self.notebook.select(0) # Switch back to Dash

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()

