import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket, threading, time, re, queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
import json, csv
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ---------------- Config ----------------
MAX_WORKERS_CAP = 200
BANNER_TIMEOUT = 0.8
UI_DRAW_INTERVAL_MS = 700    # how often GUI redraws charts & applies queued results
COMMON_SERVICES = {
    21: "FTP",22: "SSH",23: "Telnet",25: "SMTP",53: "DNS",
    80: "HTTP",110: "POP3",143: "IMAP",443: "HTTPS",445: "SMB",3389: "RDP"
}
VULN_HINTS = {
    21: "FTP — prefer SFTP/FTPS or restrict access",
    23: "Telnet — insecure, replace with SSH",
    445: "SMB — patch and restrict",
    3389: "RDP — restrict access, use MFA"
}

# ---------------- Globals ----------------
result_queue = queue.Queue()   # scanner threads push results here
results = []                   # newest-first list (protected by lock)
results_lock = threading.Lock()
pause_event = threading.Event()
stop_event = threading.Event()
executor = None
executor_lock = threading.Lock()

# ---------------- Helpers ----------------
def grab_banner(sock, timeout=BANNER_TIMEOUT):
    try:
        sock.settimeout(timeout)
        try:
            sock.sendall(b"\r\n")
        except Exception:
            pass
        data = sock.recv(2048)
        return data.decode(errors="ignore").strip() if data else ""
    except Exception:
        return ""

def scan_one(host, port):
    """Worker scan for one port. Returns result dict."""
    # honor stop/pause
    if stop_event.is_set():
        return None
    while pause_event.is_set():
        if stop_event.is_set():
            return None
        time.sleep(0.05)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        rc = s.connect_ex((host, port))
        if rc != 0:
            s.close()
            return {"port": port, "status": "CLOSED", "service": COMMON_SERVICES.get(port, "-"), "banner":"-", "hint": VULN_HINTS.get(port,"-")}
        # connected
        banner = grab_banner(s)
        s.close()
        svc = COMMON_SERVICES.get(port) or (banner.split()[0] if banner else "Unknown")
        hint = VULN_HINTS.get(port,"-")
        return {"port": port, "status": "OPEN", "service": svc, "banner": banner or "-", "hint": hint}
    except Exception as e:
        return {"port": port, "status": "ERROR", "service":"-","banner":str(e), "hint":"-"}

# ---------------- GUI App ----------------
class Theme:
    MATRIX = "matrix"
    ENTERPRISE = "enterprise"

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner (Threaded + Themes)")
        self.root.geometry("1200x760")
        self.root.minsize(1000,650)

        # ensure clean shutdown
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # layout weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        self.theme = Theme.MATRIX
        self.last_draw = 0
        self.stop_requested = False

        # toolbar
        toolbar = tk.Frame(root)
        toolbar.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        for i in range(13): toolbar.columnconfigure(i, weight=0)
        toolbar.columnconfigure(11, weight=1)

        tk.Label(toolbar, text="Target:").grid(row=0, column=0, padx=4)
        self.target_entry = tk.Entry(toolbar, width=24); self.target_entry.grid(row=0, column=1, padx=4)

        tk.Label(toolbar, text="Mode:").grid(row=0, column=2, padx=4)
        self.mode_var = tk.StringVar(value="Range")
        self.mode = ttk.Combobox(toolbar, textvariable=self.mode_var, values=("Single","Range"), width=8, state="readonly")
        self.mode.grid(row=0, column=3, padx=4); self.mode.bind("<<ComboboxSelected>>", self.on_mode)
        # port fields
        self.single_entry = tk.Entry(toolbar, width=8)
        self.start_entry = tk.Entry(toolbar, width=8); self.start_entry.grid(row=0, column=4, padx=2)
        tk.Label(toolbar, text="to").grid(row=0,column=5)
        self.end_entry = tk.Entry(toolbar, width=8); self.end_entry.grid(row=0, column=6, padx=2)

        # speed control
        tk.Label(toolbar, text="Speed:").grid(row=0, column=7, padx=4)
        self.speed_var = tk.StringVar(value="Normal")
        self.speed_combo = ttk.Combobox(toolbar, textvariable=self.speed_var, values=("Slow","Normal","Aggressive"), width=10, state="readonly")
        self.speed_combo.grid(row=0, column=8, padx=4)

        # control buttons
        self.start_btn = tk.Button(toolbar, text="▶ Start", command=self.start_scan); self.start_btn.grid(row=0,column=9,padx=4)
        self.pause_btn = tk.Button(toolbar, text="⏸ Pause", command=self.toggle_pause, state="disabled"); self.pause_btn.grid(row=0,column=10,padx=4)
        self.stop_btn = tk.Button(toolbar, text="⏹ Stop", command=self.stop_scan, state="disabled"); self.stop_btn.grid(row=0,column=11,padx=4)
        # export button
        self.export_btn = tk.Button(toolbar, text="⇩ Export", command=self.export_menu); self.export_btn.grid(row=0, column=13, padx=(6,0))

        # progress moved to toolbar (top-right)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress = ttk.Progressbar(toolbar, variable=self.progress_var, maximum=100, length=220)
        toolbar.columnconfigure(12, weight=0)
        self.progress.grid(row=0, column=12, padx=(8,0), sticky="e")

        # main frame
        main = tk.Frame(root)
        main.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        main.columnconfigure(1, weight=2); main.columnconfigure(2, weight=1); main.rowconfigure(0, weight=1)

        # left controls (info)
        left = tk.Frame(main, width=220); left.grid(row=0,column=0, sticky="nsw", padx=(0,6))
        left.grid_propagate(False)
        tk.Label(left, text="Hints", font=("Consolas",11,"bold")).pack(anchor="nw", pady=(6,4))
        for p,h in VULN_HINTS.items():
            tk.Label(left, text=f"{p}: {h}", wraplength=200, justify="left").pack(anchor="nw", padx=6, pady=2)

        # center results
        center = tk.Frame(main, bd=1, relief="sunken"); center.grid(row=0,column=1, sticky="nsew")
        center.columnconfigure(0, weight=1); center.rowconfigure(0, weight=1)
        cols = ("Port","Status","Service","Banner")
        self.tree = ttk.Treeview(center, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=150, anchor="center")
        vs = ttk.Scrollbar(center, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        center.bind("<Configure>", lambda e: self.resize_columns())

        # style tags for tree rows
        self.tree.tag_configure("open", background="#0b2f0b", foreground="#00FF41")
        self.tree.tag_configure("closed", background="#0b0b0b", foreground="#9ca3af")
        self.tree.tag_configure("error", background="#2b0b00", foreground="#ffb86b")

        # right dashboard
        right = tk.Frame(main, width=360); right.grid(row=0, column=2, sticky="nsew", padx=(6,0))
        right.grid_propagate(False)
        self.kpi_total = tk.Label(right, text="Total: 0", font=("Consolas",12,"bold")); self.kpi_total.pack(anchor="nw", pady=(8,0), padx=8)
        self.kpi_open = tk.Label(right, text="Open: 0"); self.kpi_open.pack(anchor="nw", padx=8)
        self.kpi_closed = tk.Label(right, text="Closed: 0"); self.kpi_closed.pack(anchor="nw", padx=8)
        self.kpi_vuln = tk.Label(right, text="Vulns hints: 0"); self.kpi_vuln.pack(anchor="nw", padx=8, pady=(0,8))

        # charts area (pie + bar)
        chart_area = tk.Frame(right); chart_area.pack(fill="both", expand=True, padx=7, pady=5)
        chart_area.columnconfigure(0, weight=1); chart_area.rowconfigure(0, weight=1)
        self.fig_pie = Figure(figsize=(3,1.2), dpi=90); self.ax_pie = self.fig_pie.add_subplot(111)
        self.canvas_pie = FigureCanvasTkAgg(self.fig_pie, master=chart_area); self.canvas_pie.get_tk_widget().pack(fill="both", expand=True)
        self.fig_bar = Figure(figsize=(4,2), dpi=90); self.ax_bar = self.fig_bar.add_subplot(111)
        self.canvas_bar = FigureCanvasTkAgg(self.fig_bar, master=right); self.canvas_bar.get_tk_widget().pack(fill="x", padx=6, pady=(3,6))

        # bind mousewheel to tree
        self.tree.bind_all("<MouseWheel>", self._on_mousewheel)

        # apply initial theme and schedule GUI update
        self.apply_theme()
        self.root.after(UI_DRAW_INTERVAL_MS, self.consume_queue_and_update)

    # ---------------- Theme ----------------
    def apply_theme(self):
        if self.theme == Theme.MATRIX:
            bg = "black"; fg = "#00FF41"; panel="#07110b"; fig_bg = "#000000"; bar_color = "#00FF41"
            heading_bg = "#001100"
        else:
            bg = "#f6f8fb"; fg = "#064e3b"; panel = "#ffffff"; fig_bg = "#f6f8fb"; bar_color = "#0ea5a4"
            heading_bg = "#e6fffa"

        self.root.configure(bg=bg)
        for w in (self.target_entry, self.single_entry, self.start_entry, self.end_entry):
            try:
                w.configure(bg=panel, fg=fg, insertbackground=fg)
            except Exception:
                pass
        # Treeview style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=panel, fieldbackground=panel, foreground=fg, rowheight=22)
        style.configure("Treeview.Heading", background=heading_bg, foreground=fg, font=("Consolas",11,"bold"))
        # Matplotlib style for dark/light
        if self.theme == Theme.MATRIX:
            matplotlib.rcParams.update({
                "text.color": "#00FF41", "axes.labelcolor":"#00FF41", "xtick.color":"#00FF41", "ytick.color":"#00FF41",
                "figure.facecolor": fig_bg, "axes.facecolor": fig_bg
            })
        else:
            matplotlib.rcParams.update({
                "text.color": "#0b1720", "axes.labelcolor":"#0b1720", "xtick.color":"#0b1720", "ytick.color":"#0b1720",
                "figure.facecolor": fig_bg, "axes.facecolor": fig_bg
            })
        # redraw charts
        self.draw_charts()

    def toggle_theme(self):
        self.theme = Theme.ENTERPRISE if self.theme==Theme.MATRIX else Theme.MATRIX
        self.apply_theme()

    # ---------------- Scanning ----------------
    def on_mode(self, ev=None):
        mode = self.mode_var.get()
        if mode == "Single":
            self.single_entry.grid(row=0, column=4, padx=2)
            self.start_entry.grid_forget(); self.end_entry.grid_forget()
        else:
            self.single_entry.grid_forget()
            self.start_entry.grid(row=0, column=4, padx=2); self.end_entry.grid(row=0, column=6, padx=2)

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Input error","Enter target IP/host")
            return
        # determine ports
        mode = self.mode_var.get()
        try:
            if mode == "Single":
                p = int(self.single_entry.get().strip()); ports=[p]
            else:
                s = int(self.start_entry.get().strip()); e = int(self.end_entry.get().strip())
                if s<1 or e>65535 or s>e: raise ValueError()
                ports = list(range(s,e+1))
        except Exception:
            messagebox.showerror("Input error","Invalid ports")
            return

        # pick worker count by speed
        sp = self.speed_var.get()
        if sp == "Slow":
            workers = min(8, len(ports))
        elif sp == "Aggressive":
            workers = min(MAX_WORKERS_CAP, len(ports))
        else:
            workers = min(64, len(ports))

        # reset
        with results_lock:
            results.clear()
        for it in self.tree.get_children(): self.tree.delete(it)
        self.progress_var.set(0); stop_event.clear(); pause_event.clear()
        self.start_btn.config(state="disabled"); self.pause_btn.config(state="normal"); self.stop_btn.config(state="normal")
        # start executor
        global executor
        with executor_lock:
            if executor:
                try: executor.shutdown(wait=False)
                except Exception: pass
            executor = ThreadPoolExecutor(max_workers=workers)

        # submit jobs
        total = len(ports)
        def run():
            futures = {executor.submit(scan_one, target, p): p for p in ports}
            completed = 0
            for fut in as_completed(futures):
                if stop_event.is_set(): break
                res = fut.result()
                completed += 1
                if res:
                    result_queue.put(res)    # enqueue for GUI
                # update progress
                if total:
                    self.progress_var.set((completed/total)*100)
            # finished
            self.root.after(0, self.scan_finished)

        threading.Thread(target=run, daemon=True).start()

    def toggle_pause(self):
        if pause_event.is_set():
            pause_event.clear(); self.pause_btn.config(text="⏸ Pause")
        else:
            pause_event.set(); self.pause_btn.config(text="▶ Resume")

    def stop_scan(self):
        stop_event.set(); pause_event.clear()
        self.start_btn.config(state="normal"); self.pause_btn.config(state="disabled"); self.stop_btn.config(state="disabled")
        # shutdown executor gracefully
        global executor
        with executor_lock:
            if executor:
                try:
                    executor.shutdown(wait=False)
                except Exception:
                    pass
                executor = None
        self.status_message("Stopped")

    def scan_finished(self):
        self.start_btn.config(state="normal"); self.pause_btn.config(state="disabled"); self.stop_btn.config(state="disabled")
        self.status_message("Scan complete")
        self.progress_var.set(100)

    # ---------------- Queue consumption & UI update ----------------
    def consume_queue_and_update(self):
        drew = False
        # process up to N queued results quickly but update drawing only once per interval
        processed = 0
        while not result_queue.empty() and processed < 1000:
            try:
                res = result_queue.get_nowait()
            except queue.Empty:
                break
            if res:
                with results_lock:
                    results.insert(0, res)
                self.insert_result_row(res)
            processed += 1
            drew = True
        now = time.time()*1000
        if now - self.last_draw > UI_DRAW_INTERVAL_MS:
            self.draw_charts()
            self.last_draw = now
        # schedule next consumption
        self.root.after(200, self.consume_queue_and_update)

    def insert_result_row(self, res):
        tag = "closed"
        if res["status"] == "OPEN": tag="open"
        elif res["status"] == "ERROR": tag="error"
        banner = (res["banner"][:100] + "...") if len(res.get("banner",""))>100 else res.get("banner","")
        # insert newest at top
        self.tree.insert("", 0, values=(res["port"], res["status"], res["service"], banner), tags=(tag,))
        # update KPIs
        self.update_kpis()

    def update_kpis(self):
        with results_lock:
            total = len(results); open_c = sum(1 for r in results if r["status"]=="OPEN")
            closed_c = sum(1 for r in results if r["status"]=="CLOSED")
            vuln_c = sum(1 for r in results if r.get("hint") and r.get("hint")!="-")
        self.kpi_total.config(text=f"Total: {total}")
        self.kpi_open.config(text=f"Open: {open_c}")
        self.kpi_closed.config(text=f"Closed: {closed_c}")
        self.kpi_vuln.config(text=f"Vulns hints: {vuln_c}")

    def draw_charts(self):
        with results_lock:
            copy = list(results)
        status_counts = Counter([r["status"] for r in copy])
        open_c = status_counts.get("OPEN",0); closed_c = status_counts.get("CLOSED",0); err_c = status_counts.get("ERROR",0)
        # pie
        self.ax_pie.clear()
        labels=[]; sizes=[]
        if open_c: labels.append("Open"); sizes.append(open_c)
        if closed_c: labels.append("Closed"); sizes.append(closed_c)
        if err_c: labels.append("Error"); sizes.append(err_c)
        if sizes:
            colors = [("#00FF41" if self.theme==Theme.MATRIX else "#10b981"),
                      ("#004400" if self.theme==Theme.MATRIX else "#6b7280"),
                      "#f97316"]
            self.ax_pie.pie(sizes, labels=labels, colors=colors[:len(sizes)], autopct="%1.0f%%",
                            textprops={"color":("#00FF41" if self.theme==Theme.MATRIX else "#0f172a")})
        else:
            self.ax_pie.text(0.5,0.5,"No data", ha="center", color=("#00FF41" if self.theme==Theme.MATRIX else "#0f172a"))
        self.ax_pie.set_facecolor("#000000" if self.theme==Theme.MATRIX else "#f6f8fb")
        self.canvas_pie.draw()

        # bar: service counts
        svc_counts = Counter([r["service"] for r in copy if r.get("service") and r["service"]!="-"])
        top = svc_counts.most_common(6)
        labels = [t[0] for t in top]; vals = [t[1] for t in top]
        self.ax_bar.clear()
        if vals:
            cols = [("#00FF41" if self.theme==Theme.MATRIX else "#0ea5a4")] * len(vals)
            x = list(range(len(labels)))
            self.ax_bar.bar(x, vals, color=cols)
            self.ax_bar.set_xticks(x)
            self.ax_bar.set_xticklabels(labels, rotation=30, ha="right", color=("#00FF41" if self.theme==Theme.MATRIX else "#0f172a"))
        else:
            self.ax_bar.text(0.5,0.5,"No service data", ha="center", color=("#00FF41" if self.theme==Theme.MATRIX else "#0f172a"))
        self.ax_bar.set_facecolor("#000000" if self.theme==Theme.MATRIX else "#f6f8fb")
        self.canvas_bar.draw()

    # ---------------- Misc ----------------
    def resize_columns(self):
        total_w = self.tree.winfo_width() - 30
        if total_w <= 0: return
        widths = [0.12, 0.12, 0.28, 0.48]
        cols = ("Port","Status","Service","Banner")
        for i,c in enumerate(cols):
            self.tree.column(c, width=max(80,int(total_w*widths[i])))

    def _on_mousewheel(self, event):
        try:
            self.tree.yview_scroll(int(-1*(event.delta/120)), "units")
        except Exception:
            pass

    def status_message(self, txt):
        # placeholder - you can place status text somewhere if needed
        print("[STATUS]", txt)

    # ---------------- Export helpers ----------------
    def export_menu(self):
        """Simple dialog: CSV or JSON. You can extend further."""
        choice = messagebox.askquestion("Export", "Export results as CSV? (No -> JSON)")
        if choice == "yes":
            self.export_csv()
        else:
            self.export_json()

    def export_csv(self):
        with results_lock:
            data = list(results)  # newest-first (same as UI)
        if not data:
            messagebox.showwarning("No data", "No results to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv"),("All files","*.*")])
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["port","status","service","banner","hint"])
                for r in data:
                    writer.writerow([r.get("port"), r.get("status"), r.get("service"), r.get("banner"), r.get("hint","-")])
            messagebox.showinfo("Exported", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def export_json(self):
        with results_lock:
            data = list(results)
        if not data:
            messagebox.showwarning("No data", "No results to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json"),("All files","*.*")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Exported", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def on_close(self):
        """Stop scanning, shutdown executor, then close."""
        if messagebox.askokcancel("Quit", "Stop scanning and quit?"):
            stop_event.set()
            pause_event.clear()
            global executor
            with executor_lock:
                if executor:
                    try:
                        executor.shutdown(wait=False)
                    except Exception:
                        pass
                    executor = None
            # allow any UI cleanup if necessary
            self.root.destroy()

# ----------------- main -----------------
def main():
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
