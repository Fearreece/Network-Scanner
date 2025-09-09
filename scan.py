# # """
# # enterprise_vuln_scanner.py
# # Enterprise SIEM-like Network Scanner + Service Detection + NVD lookup (no API key required)
# # - Live updating dashboard + charts
# # - Aggressive but lightweight protocol probes for service detection
# # - NVD CVE lookups (best-effort, cached, rate-limited), top 5 results per product+version
# # - Pause/Resume, Stop, Export, responsive UI, colorful and polished buttons
# # """

# # import socket
# # import threading
# # import time
# # import re
# # import json
# # import csv
# # from concurrent.futures import ThreadPoolExecutor, as_completed
# # from collections import Counter, defaultdict
# # from urllib.parse import quote_plus

# # import tkinter as tk
# # from tkinter import ttk, messagebox, filedialog

# # import requests
# # import matplotlib
# # matplotlib.use("TkAgg")
# # from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# # from matplotlib.figure import Figure

# # # ----------------- Configuration -----------------
# # MAX_WORKERS = 80            # concurrent port workers (tune for your machine)
# # BANNER_TIMEOUT = 1.0        # seconds to wait for banner grab
# # NVD_SLEEP = 0.6             # seconds between NVD queries to avoid hitting rate limits
# # TOP_CVE_PER_PRODUCT = 5     # number of CVEs to show per product+version lookup

# # # A friendly map of common service names (fallback)
# # COMMON_SERVICES = {
# #     20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
# #     53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
# #     143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
# #     993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP"
# # }

# # # Probes for common protocols: (port set or predicate, probe bytes or function)
# # PROTOCOL_PROBES = {
# #     # HTTP: send HEAD
# #     80: b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n",
# #     8080: b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n",
# #     443: b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n",
# #     # SMTP: EHLO
# #     25: b"EHLO scan.example\r\n",
# #     # FTP: FEAT (many servers respond to just connecting)
# #     21: b"FEAT\r\n",
# #     # POP3: CAPA
# #     110: b"CAPA\r\n",
# #     # IMAP: CAPABILITY
# #     143: b"CAPABILITY\r\n",
# # }

# # # Banner patterns (product + version extraction)
# # BANNER_PATTERNS = [
# #     (re.compile(r"(?P<name>Apache)[/ \-]?(?P<version>\d+(\.\d+)+)", re.I), "apache"),
# #     (re.compile(r"(?P<name>OpenSSH)[_\-\/]?(?P<version>\d+(\.\d+)+)", re.I), "openssh"),
# #     (re.compile(r"(?P<name>nginx)[/ \-]?(?P<version>\d+(\.\d+)+)", re.I), "nginx"),
# #     (re.compile(r"(?P<name>Microsoft-IIS)[/ \-]?(?P<version>\d+(\.\d+)+)", re.I), "iis"),
# #     (re.compile(r"(?P<name>Tomcat)[/ ]?(?P<version>\d+(\.\d+)+)", re.I), "tomcat"),
# # ]

# # # Vulnerability hint fallbacks for very common risky ports
# # VULN_HINTS = {
# #     21: "FTP - consider SFTP/FTPS or restrict access",
# #     23: "Telnet - insecure, replace with SSH",
# #     445: "SMB - ensure patched and restrict to LAN",
# #     3389: "RDP - restrict access, use MFA",
# # }

# # # ----------------- Globals -----------------
# # results = []                 # newest-first list of dicts
# # results_lock = threading.Lock()
# # pause_event = threading.Event()
# # stop_event = threading.Event()

# # # CVE lookup cache: product|version -> list of CVE dicts
# # cve_cache = {}
# # cve_cache_lock = threading.Lock()

# # # ----------------- NVD Query (no API key required, rate-limited + cached) -----------------
# # def query_nvd(product, version, limit=TOP_CVE_PER_PRODUCT):
# #     """
# #     Query NVD for product+version. Works without API key but is rate-limited by NVD.
# #     Returns list of dicts: {"id":..., "summary":..., "score":...}
# #     """
# #     if not product or not version:
# #         return []
# #     key = f"{product} {version}".strip().lower()
# #     with cve_cache_lock:
# #         if key in cve_cache:
# #             return cve_cache[key]

# #     # build search query (keywordSearch)
# #     query = quote_plus(f"{product} {version}")
# #     url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage={limit}"
# #     try:
# #         # make request (no API key) - best effort
# #         r = requests.get(url, timeout=10)
# #         if r.status_code != 200:
# #             # cache empty result to avoid repeated rapid calls
# #             with cve_cache_lock:
# #                 cve_cache[key] = []
# #             return []
# #         data = r.json()
# #         items = data.get("vulnerabilities") or data.get("vulnerabilities", [])
# #         out = []
# #         # NVD v2.0 structure: vulnerabilities -> vuln -> cve -> metrics
# #         for item in items[:limit]:
# #             cve = item.get("cve") or {}
# #             cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID") or ""
# #             desc = ""
# #             descriptions = cve.get("descriptions", [])
# #             if descriptions and isinstance(descriptions, list):
# #                 desc = descriptions[0].get("value", "")
# #             # Try to find CVSS score
# #             score = ""
# #             metrics = cve.get("metrics", {})
# #             # check v3 then v2
# #             cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
# #             if cvss_v3 and isinstance(cvss_v3, list) and cvss_v3:
# #                 score = cvss_v3[0].get("cvssData", {}).get("baseScore", "")
# #             # fallback v2
# #             if not score:
# #                 cvss_v2 = metrics.get("cvssMetricV2")
# #                 if cvss_v2 and isinstance(cvss_v2, list) and cvss_v2:
# #                     score = cvss_v2[0].get("cvssData", {}).get("baseScore", "")
# #             out.append({"id": cve_id, "summary": desc, "score": score})
# #         # rate-limit to be nice
# #         time.sleep(NVD_SLEEP)
# #         with cve_cache_lock:
# #             cve_cache[key] = out
# #         return out
# #     except Exception:
# #         with cve_cache_lock:
# #             cve_cache[key] = []
# #         return []

# # # ----------------- Service detection (aggressive probes) -----------------
# # def probe_and_banner(host, port, sock):
# #     """
# #     Send probes depending on port. Return banner text (best-effort).
# #     sock is a connected socket object.
# #     """
# #     try:
# #         # if known probe exists for this port, send it
# #         probe = PROTOCOL_PROBES.get(port)
# #         if probe:
# #             try:
# #                 sock.sendall(probe)
# #             except Exception:
# #                 pass
# #         else:
# #             # generic probe: newline to prompt some services
# #             try:
# #                 sock.sendall(b"\r\n")
# #             except Exception:
# #                 pass

# #         # attempt to read response
# #         sock.settimeout(BANNER_TIMEOUT)
# #         data = b""
# #         try:
# #             data = sock.recv(4096)
# #         except Exception:
# #             # no banner
# #             pass
# #         return data.decode(errors="ignore").strip() if data else ""
# #     except Exception:
# #         return ""

# # def parse_banner_for_product(banner):
# #     """Extract (product, version) from banner using patterns or heuristic."""
# #     if not banner:
# #         return (None, None)
# #     for pat, _ in BANNER_PATTERNS:
# #         m = pat.search(banner)
# #         if m:
# #             name = m.groupdict().get("name")
# #             version = m.groupdict().get("version")
# #             return (name, version)
# #     # fallback heuristic: look for 'product/version'
# #     m = re.search(r"(?P<name>[A-Za-z0-9\-_]+)[/ ](?P<version>\d+(\.\d+)+)", banner)
# #     if m:
# #         return (m.group('name'), m.group('version'))
# #     return (None, None)

# # # ----------------- single port scan logic -----------------
# # def scan_port_worker(host, port):
# #     """Scans one port. Respects pause_event & stop_event. Returns dict or None if stopped."""
# #     if stop_event.is_set():
# #         return None
# #     # pause support
# #     while pause_event.is_set():
# #         if stop_event.is_set():
# #             return None
# #         time.sleep(0.1)

# #     try:
# #         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         s.settimeout(1.0)
# #         rc = s.connect_ex((host, port))
# #         if rc != 0:
# #             s.close()
# #             return {"port": port, "status": "CLOSED", "service": COMMON_SERVICES.get(port, "-"), "banner": "-", "product": "-", "version": "-", "cves": []}
# #         # connected -> try aggressive probes & banner
# #         banner = probe_and_banner(host, port, s)
# #         # if still empty and common HTTPS port, use TLS handshake approach? (skipped, keep lightweight)
# #         product, version = parse_banner_for_product(banner)
# #         # fallback to known service name
# #         service = product or COMMON_SERVICES.get(port, "Unknown")
# #         cves = []
# #         if product and version:
# #             cves = query_nvd(product, version)
# #         s.close()
# #         return {"port": port, "status": "OPEN", "service": service, "banner": banner or "-", "product": product or "-", "version": version or "-", "cves": cves}
# #     except Exception as e:
# #         return {"port": port, "status": "ERROR", "service": "-", "banner": str(e), "product": "-", "version": "-", "cves": []}

# # # ----------------- GUI App -----------------
# # class EnterpriseScannerGUI:
# #     def __init__(self, root):
# #         self.root = root
# #         self.root.title("Enterprise Vulnerability Scanner (SIEM-style)")
# #         self.root.geometry("1240x820")
# #         # responsive grid
# #         self.root.columnconfigure(0, weight=1)
# #         self.root.rowconfigure(1, weight=1)

# #         # Styles (polished)
# #         self.style = ttk.Style()
# #         self.style.theme_use("clam")
# #         # Button style
# #         self.style.configure("TButton", font=("Segoe UI", 10, "bold"))
# #         self.style.configure("Accent.TButton", background="#0ea5a4", foreground="white")
# #         # Treeview style
# #         self.style.configure("Treeview", rowheight=24, font=("Consolas", 10))
# #         self.style.map("TButton", foreground=[('active','white')])

# #         # Top toolbar with inputs and controls
# #         toolbar = tk.Frame(root, bg="#ffffff", padx=10, pady=8)
# #         toolbar.grid(row=0, column=0, sticky="ew")
# #         toolbar.columnconfigure(12, weight=1)

# #         tk.Label(toolbar, text="Target (IP/Host):", bg="#ffffff", font=("Segoe UI",10)).grid(row=0, column=0, padx=4)
# #         self.target_entry = tk.Entry(toolbar, width=28, font=("Segoe UI",10))
# #         self.target_entry.grid(row=0, column=1, padx=4)

# #         tk.Label(toolbar, text="Start Port:", bg="#ffffff", font=("Segoe UI",10)).grid(row=0, column=2, padx=4)
# #         self.start_entry = tk.Entry(toolbar, width=8, font=("Segoe UI",10))
# #         self.start_entry.grid(row=0, column=3, padx=4)
# #         tk.Label(toolbar, text="End Port:", bg="#ffffff", font=("Segoe UI",10)).grid(row=0, column=4, padx=4)
# #         self.end_entry = tk.Entry(toolbar, width=8, font=("Segoe UI",10))
# #         self.end_entry.grid(row=0, column=5, padx=4)

# #         self.start_btn = ttk.Button(toolbar, text="Start", command=self.start_scan, style="Accent.TButton")
# #         self.start_btn.grid(row=0, column=6, padx=6)
# #         self.pause_btn = ttk.Button(toolbar, text="Pause", command=self.toggle_pause, state="disabled")
# #         self.pause_btn.grid(row=0, column=7, padx=6)
# #         self.stop_btn = ttk.Button(toolbar, text="Stop", command=self.stop_scan, state="disabled")
# #         self.stop_btn.grid(row=0, column=8, padx=6)
# #         ttk.Button(toolbar, text="Export JSON", command=lambda: self.export_results("json")).grid(row=0,column=9, padx=6)
# #         ttk.Button(toolbar, text="Export CSV", command=lambda: self.export_results("csv")).grid(row=0,column=10, padx=6)

# #         self.status_label = tk.Label(toolbar, text="Idle", bg="#ffffff", font=("Segoe UI",9))
# #         self.status_label.grid(row=0, column=11, padx=6)

# #         # Notebook for tabs
# #         self.notebook = ttk.Notebook(root)
# #         self.notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

# #         # Dashboard tab (first)
# #         self._create_dashboard_tab()
# #         # Scan Results tab
# #         self._create_scan_tab()
# #         # Vulnerabilities tab
# #         self._create_vuln_tab()

# #         # chart update every second
# #         self.chart_interval_ms = 1000
# #         self._schedule_chart_update()

# #         # executor ref
# #         self.executor = None

# #     def _create_dashboard_tab(self):
# #         dash = ttk.Frame(self.notebook)
# #         self.notebook.add(dash, text="Dashboard")
# #         dash.columnconfigure(0, weight=1)
# #         dash.rowconfigure(1, weight=1)

# #         # KPI strip
# #         kpi_strip = tk.Frame(dash, bg="#f8fafc", padx=8, pady=8)
# #         kpi_strip.grid(row=0, column=0, sticky="ew", padx=4, pady=6)
# #         for i in range(4):
# #             kpi_strip.columnconfigure(i, weight=1)

# #         self.kpi_total = self._make_kpi(kpi_strip, "Total Scanned", "0", 0, "#eef2ff")
# #         self.kpi_open = self._make_kpi(kpi_strip, "Open Ports", "0", 1, "#ecfdf5")
# #         self.kpi_closed = self._make_kpi(kpi_strip, "Closed Ports", "0", 2, "#f8fafc")
# #         self.kpi_vuln = self._make_kpi(kpi_strip, "Vulnerabilities", "0", 3, "#fff1f2")

# #         # graph area
# #         graph_area = tk.Frame(dash, bg="#ffffff")
# #         graph_area.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
# #         graph_area.columnconfigure(0, weight=1)
# #         graph_area.columnconfigure(1, weight=1)
# #         graph_area.rowconfigure(0, weight=1)

# #         # pie
# #         pie_card = tk.LabelFrame(graph_area, text="Port Status", padx=6, pady=6)
# #         pie_card.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
# #         self.fig_pie = Figure(figsize=(4,3), dpi=100)
# #         self.ax_pie = self.fig_pie.add_subplot(111)
# #         self.canvas_pie = FigureCanvasTkAgg(self.fig_pie, master=pie_card)
# #         self.canvas_pie.get_tk_widget().pack(expand=True, fill="both")

# #         # bar
# #         bar_card = tk.LabelFrame(graph_area, text="Vulnerability Severity", padx=6, pady=6)
# #         bar_card.grid(row=0, column=1, sticky="nsew", padx=6, pady=6)
# #         self.fig_bar = Figure(figsize=(5,3), dpi=100)
# #         self.ax_bar = self.fig_bar.add_subplot(111)
# #         self.canvas_bar = FigureCanvasTkAgg(self.fig_bar, master=bar_card)
# #         self.canvas_bar.get_tk_widget().pack(expand=True, fill="both")

# #     def _make_kpi(self, parent, title, value, col, bg):
# #         f = tk.Frame(parent, bg=bg, padx=10, pady=8, relief="groove", bd=1)
# #         f.grid(row=0, column=col, sticky="nsew", padx=6)
# #         tk.Label(f, text=title, bg=bg, fg="#111827", font=("Segoe UI", 10)).pack(anchor="w")
# #         lbl = tk.Label(f, text=value, bg=bg, fg="#0f172a", font=("Segoe UI", 20, "bold"))
# #         lbl.pack(anchor="w", pady=(8,0))
# #         return lbl

# #     def _create_scan_tab(self):
# #         scan_tab = ttk.Frame(self.notebook)
# #         self.notebook.add(scan_tab, text="Scan Results")
# #         scan_tab.columnconfigure(0, weight=1)
# #         scan_tab.rowconfigure(0, weight=1)

# #         container = tk.Frame(scan_tab, bg="#ffffff")
# #         container.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
# #         container.columnconfigure(0, weight=1)
# #         container.rowconfigure(0, weight=1)

# #         cols = ("Port","Status","Service","Banner")
# #         tree = ttk.Treeview(container, columns=cols, show="headings")
# #         vs = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
# #         tree.configure(yscroll=vs.set)
# #         for c in cols:
# #             tree.heading(c, text=c, anchor="center")
# #             tree.column(c, anchor="center", width=220)
# #         tree.grid(row=0, column=0, sticky="nsew")
# #         vs.grid(row=0, column=1, sticky="ns")
# #         self.trees = {"scan": tree}
# #         # tags/colors
# #         tree.tag_configure("open", foreground="#065f46")       # green
# #         tree.tag_configure("closed", foreground="#6b7280")     # gray
# #         tree.tag_configure("error", foreground="#b45309")      # orange
# #         tree.tag_configure("critical", foreground="#b91c1c")   # red
# #         self._bind_mousewheel(tree)

# #     def _create_vuln_tab(self):
# #         vtab = ttk.Frame(self.notebook)
# #         self.notebook.add(vtab, text="Vulnerabilities")
# #         vtab.columnconfigure(0, weight=1)
# #         vtab.rowconfigure(0, weight=1)

# #         cont = tk.Frame(vtab, bg="#ffffff")
# #         cont.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
# #         cont.columnconfigure(0, weight=1)
# #         cont.rowconfigure(0, weight=1)

# #         cols = ("Port","Service","CVE ID","Severity","Description")
# #         tree = ttk.Treeview(cont, columns=cols, show="headings")
# #         vs = ttk.Scrollbar(cont, orient="vertical", command=tree.yview)
# #         tree.configure(yscroll=vs.set)
# #         for c in cols:
# #             tree.heading(c, text=c, anchor="center")
# #             tree.column(c, anchor="center", width=220)
# #         tree.grid(row=0, column=0, sticky="nsew")
# #         vs.grid(row=0, column=1, sticky="ns")
# #         self.vuln_tree = tree
# #         # vuln tags
# #         tree.tag_configure("critical", foreground="#b91c1c")
# #         tree.tag_configure("high", foreground="#c2410c")
# #         tree.tag_configure("medium", foreground="#b45309")
# #         tree.tag_configure("low", foreground="#0b69a3")
# #         self._bind_mousewheel(tree)

# #     def _bind_mousewheel(self, widget):
# #         def _on_mousewheel(event):
# #             try:
# #                 widget.yview_scroll(int(-1*(event.delta/120)), "units")
# #             except Exception:
# #                 if getattr(event, "num", None) == 5:
# #                     widget.yview_scroll(1, "units")
# #                 elif getattr(event, "num", None) == 4:
# #                     widget.yview_scroll(-1, "units")
# #         widget.bind_all("<MouseWheel>", _on_mousewheel)
# #         widget.bind_all("<Button-4>", _on_mousewheel)
# #         widget.bind_all("<Button-5>", _on_mousewheel)

# #     # ---------------- scanning control ----------------
# #     def start_scan(self):
# #         target = self.target_entry.get().strip()
# #         if not target:
# #             messagebox.showerror("Input error", "Enter a target IP or hostname")
# #             return
# #         try:
# #             start_p = int(self.start_entry.get().strip())
# #             end_p = int(self.end_entry.get().strip())
# #         except Exception:
# #             messagebox.showerror("Input error", "Enter numeric start/end ports")
# #             return
# #         if start_p < 1 or end_p > 65535 or start_p > end_p:
# #             messagebox.showerror("Input error", "Enter a valid port range (1-65535)")
# #             return

# #         # reset state
# #         with results_lock:
# #             results.clear()
# #         self.trees["scan"].delete(*self.trees["scan"].get_children())
# #         self.vuln_tree.delete(*self.vuln_tree.get_children())
# #         stop_event.clear()
# #         pause_event.clear()

# #         # buttons
# #         self.start_btn.config(state="disabled")
# #         self.pause_btn.config(state="normal", text="Pause")
# #         self.stop_btn.config(state="normal")
# #         self.status_label.config(text=f"Scanning {target} ...")

# #         total = max(1, end_p - start_p + 1)
# #         self.executor = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total))

# #         # run scan loop in background
# #         def scan_loop():
# #             futures = {self.executor.submit(scan_port_worker, target, p): p for p in range(start_p, end_p+1)}
# #             completed = 0
# #             for fut in as_completed(futures):
# #                 if stop_event.is_set():
# #                     break
# #                 res = fut.result()
# #                 completed += 1
# #                 # insert result
# #                 if res:
# #                     with results_lock:
# #                         results.insert(0, res)
# #                     self._insert_scan_result(res)
# #                 # update KPI counts
# #                 self._update_kpis()
# #             # finished/cleanup
# #             self._on_scan_finished()

# #         threading.Thread(target=scan_loop, daemon=True).start()
# #         # show dashboard first
# #         self.notebook.select(0)

# #     def toggle_pause(self):
# #         if pause_event.is_set():
# #             pause_event.clear()
# #             self.pause_btn.config(text="Pause")
# #             self.status_label.config(text="Resumed")
# #         else:
# #             pause_event.set()
# #             self.pause_btn.config(text="Resume")
# #             self.status_label.config(text="Paused")

# #     def stop_scan(self):
# #         stop_event.set()
# #         pause_event.clear()
# #         self.start_btn.config(state="normal")
# #         self.pause_btn.config(state="disabled", text="Pause")
# #         self.stop_btn.config(state="disabled")
# #         self.status_label.config(text="Stopped")

# #     def _insert_scan_result(self, res):
# #         # UI insert on main thread
# #         def ui():
# #             tag = "closed"
# #             if res["status"] == "OPEN":
# #                 tag = "open"
# #             elif res["status"] == "ERROR":
# #                 tag = "error"
# #             display_banner = (res["banner"][:70] + "...") if len(res["banner"])>70 else res["banner"]
# #             self.trees["scan"].insert("", 0, values=(res["port"], res["status"], res["service"], display_banner), tags=(tag,))
# #             # vulnerabilities if present
# #             if res.get("cves"):
# #                 # limit to top K
# #                 for c in res["cves"][:TOP_CVE_PER_PRODUCT]:
# #                     cve_id = c.get("id") or "-"
# #                     score = c.get("score") or ""
# #                     summary = (c.get("summary") or "")[:140]
# #                     tag_v = self._sev_tag(score)
# #                     self.vuln_tree.insert("", 0, values=(res["port"], res["service"], cve_id, score, summary), tags=(tag_v,))
# #             # scroll newest to top
# #             try:
# #                 self.trees["scan"].yview_moveto(0)
# #             except Exception:
# #                 pass
# #             try:
# #                 self.vuln_tree.yview_moveto(0)
# #             except Exception:
# #                 pass
# #         self.root.after(0, ui)

# #     def _sev_tag(self, score):
# #         try:
# #             s = float(score)
# #         except Exception:
# #             return "low"
# #         if s >= 9.0:
# #             return "critical"
# #         if s >= 7.0:
# #             return "high"
# #         if s >= 4.0:
# #             return "medium"
# #         return "low"

# #     def _update_kpis(self):
# #         with results_lock:
# #             total = len(results)
# #             open_count = sum(1 for r in results if r["status"]=="OPEN")
# #             closed_count = sum(1 for r in results if r["status"]=="CLOSED")
# #             vuln_count = sum(len(r.get("cves",[])) for r in results)
# #         def ui():
# #             self.kpi_total.config(text=str(total))
# #             self.kpi_open.config(text=str(open_count))
# #             self.kpi_closed.config(text=str(closed_count))
# #             self.kpi_vuln.config(text=str(vuln_count))
# #         self.root.after(0, ui)

# #     def _on_scan_finished(self):
# #         def ui():
# #             self.start_btn.config(state="normal")
# #             self.pause_btn.config(state="disabled", text="Pause")
# #             self.stop_btn.config(state="disabled")
# #             self.status_label.config(text="Scan complete")
# #             self._update_kpis()
# #         self.root.after(0, ui)

# #     # Charts: live update
# #     def _schedule_chart_update(self):
# #         self._update_charts()
# #         self.root.after(self.chart_interval_ms, self._schedule_chart_update)

# #     def _update_charts(self):
# #         with results_lock:
# #             copy = list(results)
# #         status_counts = Counter([r["status"] for r in copy])
# #         open_c = status_counts.get("OPEN", 0)
# #         closed_c = status_counts.get("CLOSED", 0)
# #         err_c = status_counts.get("ERROR", 0)

# #         # pie
# #         self.ax_pie.clear()
# #         labels = []
# #         sizes = []
# #         colors = []
# #         if open_c:
# #             labels.append("Open")
# #             sizes.append(open_c)
# #             colors.append("#16a34a")  # green
# #         if closed_c:
# #             labels.append("Closed")
# #             sizes.append(closed_c)
# #             colors.append("#6b7280")  # gray
# #         if err_c:
# #             labels.append("Error")
# #             sizes.append(err_c)
# #             colors.append("#f97316")  # orange
# #         if sizes:
# #             self.ax_pie.pie(sizes, labels=labels, colors=colors, autopct="%1.0f%%")
# #         else:
# #             self.ax_pie.text(0.5, 0.5, "No data", ha="center")
# #         self.ax_pie.set_title("Port Status Distribution")
# #         self.canvas_pie.draw()

# #         # vuln severity bar
# #         sev_counts = defaultdict(int)
# #         for r in copy:
# #             for c in r.get("cves", []):
# #                 sc = c.get("score") or ""
# #                 try:
# #                     s = float(sc)
# #                 except Exception:
# #                     s = 0.0
# #                 if s >= 9.0:
# #                     sev_counts["Critical"] += 1
# #                 elif s >= 7.0:
# #                     sev_counts["High"] += 1
# #                 elif s >= 4.0:
# #                     sev_counts["Medium"] += 1
# #                 else:
# #                     sev_counts["Low/Info"] += 1
# #         cats = ["Critical","High","Medium","Low/Info"]
# #         vals = [sev_counts.get(x,0) for x in cats]
# #         bar_colors = ["#ef4444","#f97316","#fbbf24","#60a5fa"]
# #         self.ax_bar.clear()
# #         self.ax_bar.bar(cats, vals, color=bar_colors)
# #         self.ax_bar.set_title("Vulnerability Severity Counts")
# #         self.canvas_bar.draw()

# #     def export_results(self, kind):
# #         with results_lock:
# #             copy = list(results)
# #         if not copy:
# #             messagebox.showwarning("No data", "No results to export")
# #             return
# #         path = filedialog.asksaveasfilename(defaultextension=".json" if kind=="json" else ".csv")
# #         if not path:
# #             return
# #         try:
# #             if kind=="json":
# #                 with open(path, "w", encoding="utf-8") as f:
# #                     json.dump(copy, f, indent=2)
# #             else:
# #                 with open(path, "w", newline="", encoding="utf-8") as f:
# #                     writer = csv.writer(f)
# #                     writer.writerow(["port","status","service","banner","product","version","cve_ids"])
# #                     for r in copy:
# #                         cves = ";".join([c.get("id","") for c in r.get("cves",[])]) or "-"
# #                         writer.writerow([r["port"], r["status"], r["service"], r["banner"], r["product"], r["version"], cves])
# #             messagebox.showinfo("Exported", f"Saved to {path}")
# #         except Exception as e:
# #             messagebox.showerror("Export failed", str(e))

# # # ----------------- main -----------------
# # def main():
# #     root = tk.Tk()
# #     app = EnterpriseScannerGUI(root)
# #     root.mainloop()

# # if __name__ == "__main__":
# #     main()







# import tkinter as tk
# from tkinter import ttk, messagebox
# import socket
# import threading
# import requests
# import urllib.parse
# import matplotlib.pyplot as plt
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# # ------------------ Vulnerability Lookup ------------------
# def fetch_vulnerabilities(service):
#     try:
#         query = urllib.parse.quote(service)
#         url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
#         response = requests.get(url, timeout=10)
#         if response.status_code == 200:
#             data = response.json()
#             vulns = []
#             for item in data.get("vulnerabilities", [])[:5]:  # Top 5 results
#                 cve = item["cve"]
#                 vuln_id = cve.get("id", "Unknown")
#                 desc = cve.get("descriptions", [{}])[0].get("value", "No description")
#                 metrics = cve.get("metrics", {})
#                 severity = "Unknown"
#                 if "cvssMetricV31" in metrics:
#                     severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
#                 vulns.append((vuln_id, severity, desc))
#             return vulns
#     except:
#         return []
#     return []

# # ------------------ Port Scanner ------------------
# class PortScanner:
#     def __init__(self, gui):
#         self.gui = gui
#         self.stop_flag = False

#     def scan_port(self, target, port):
#         try:
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.settimeout(1)
#             result = sock.connect_ex((target, port))
#             if result == 0:
#                 try:
#                     banner = sock.recv(1024).decode().strip()
#                 except:
#                     banner = "Unknown"
#                 service = socket.getservbyport(port, "tcp") if port in range(1, 1025) else "Unknown"
#                 self.gui.add_result(port, "Open", service, banner)
#                 # Fetch vulnerabilities for service
#                 vulns = fetch_vulnerabilities(service)
#                 for v in vulns:
#                     self.gui.add_vulnerability(port, service, v[0], v[1], v[2])
#             else:
#                 self.gui.add_result(port, "Closed", "-", "-")
#             sock.close()
#         except:
#             self.gui.add_result(port, "Error", "-", "-")

#     def start_scan(self, target, ports):
#         for port in ports:
#             if self.stop_flag:
#                 break
#             self.scan_port(target, port)
#         self.gui.finish_scan()

#     def stop_scan(self):
#         self.stop_flag = True

# # ------------------ GUI ------------------
# class ScannerGUI:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Hacker-Style Port & Vulnerability Scanner")
#         self.root.geometry("1200x700")
#         self.root.configure(bg="black")

#         style = ttk.Style()
#         style.theme_use("clam")
#         style.configure("Treeview", background="black", foreground="#00FF41",
#                         fieldbackground="black", rowheight=25, font=("Consolas", 11))
#         style.map("Treeview", background=[("selected", "#004400")])
#         style.configure("Treeview.Heading", foreground="#00FF41", background="black", font=("Consolas", 12, "bold"))

#         self.notebook = ttk.Notebook(root)
#         self.notebook.pack(fill="both", expand=True)

#         self.dashboard_frame = tk.Frame(self.notebook, bg="black")
#         self.results_frame = tk.Frame(self.notebook, bg="black")
#         self.vulns_frame = tk.Frame(self.notebook, bg="black")

#         self.notebook.add(self.dashboard_frame, text="📊 Dashboard")
#         self.notebook.add(self.results_frame, text="📜 Scan Results")
#         self.notebook.add(self.vulns_frame, text="⚠ Vulnerabilities")

#         self.setup_dashboard()
#         self.setup_results()
#         self.setup_vulnerabilities()
#         self.setup_controls()

#         self.scanner = PortScanner(self)

#     def setup_controls(self):
#         control_frame = tk.Frame(self.root, bg="black")
#         control_frame.pack(fill="x")

#         tk.Label(control_frame, text="Target:", fg="#00FF41", bg="black", font=("Consolas", 12)).pack(side="left")
#         self.target_entry = tk.Entry(control_frame, bg="black", fg="#00FF41", insertbackground="white")
#         self.target_entry.pack(side="left", padx=5)

#         # Dropdown for port selection
#         self.mode_var = tk.StringVar(value="Range")
#         self.mode_dropdown = ttk.Combobox(control_frame, textvariable=self.mode_var,
#                                           values=["Single Port", "Range"], state="readonly")
#         self.mode_dropdown.pack(side="left", padx=5)
#         self.mode_dropdown.bind("<<ComboboxSelected>>", self.toggle_port_mode)

#         self.port_entry_single = tk.Entry(control_frame, bg="black", fg="#00FF41", insertbackground="white")
#         self.port_entry_start = tk.Entry(control_frame, bg="black", fg="#00FF41", insertbackground="white")
#         self.port_entry_end = tk.Entry(control_frame, bg="black", fg="#00FF41", insertbackground="white")

#         self.port_entry_start.pack(side="left", padx=5)
#         self.port_entry_end.pack(side="left", padx=5)

#         self.scan_button = tk.Button(control_frame, text="▶ Start Scan", command=self.start_scan,
#                                      bg="black", fg="#00FF41", font=("Consolas", 12), relief="ridge")
#         self.scan_button.pack(side="left", padx=5)

#         self.stop_button = tk.Button(control_frame, text="⏸ Pause", command=self.stop_scan,
#                                      bg="black", fg="#00FF41", font=("Consolas", 12), relief="ridge")
#         self.stop_button.pack(side="left", padx=5)

#     def toggle_port_mode(self, event=None):
#         mode = self.mode_var.get()
#         if mode == "Single Port":
#             self.port_entry_start.pack_forget()
#             self.port_entry_end.pack_forget()
#             self.port_entry_single.pack(side="left", padx=5)
#         else:
#             self.port_entry_single.pack_forget()
#             self.port_entry_start.pack(side="left", padx=5)
#             self.port_entry_end.pack(side="left", padx=5)

#     def setup_dashboard(self):
#         self.dashboard_label = tk.Label(self.dashboard_frame, text="Scan Dashboard",
#                                         fg="#00FF41", bg="black", font=("Consolas", 16, "bold"))
#         self.dashboard_label.pack()

#         self.stats_label = tk.Label(self.dashboard_frame, text="No scans yet.",
#                                     fg="#00FF41", bg="black", font=("Consolas", 12))
#         self.stats_label.pack(pady=20)

#         fig, self.ax = plt.subplots(figsize=(5, 4), facecolor="black")
#         self.ax.set_facecolor("black")
#         self.canvas = FigureCanvasTkAgg(fig, master=self.dashboard_frame)
#         self.canvas.get_tk_widget().pack()

#     def setup_results(self):
#         self.tree = ttk.Treeview(self.results_frame, columns=("Port", "Status", "Service", "Banner"), show="headings")
#         for col in ("Port", "Status", "Service", "Banner"):
#             self.tree.heading(col, text=col)
#             self.tree.column(col, width=150)
#         self.tree.pack(fill="both", expand=True)

#     def setup_vulnerabilities(self):
#         self.vuln_tree = ttk.Treeview(self.vulns_frame,
#                                       columns=("Port", "Service", "CVE", "Severity", "Description"), show="headings")
#         for col in ("Port", "Service", "CVE", "Severity", "Description"):
#             self.vuln_tree.heading(col, text=col)
#             self.vuln_tree.column(col, width=200)
#         self.vuln_tree.pack(fill="both", expand=True)

#     def add_result(self, port, status, service, banner):
#         self.tree.insert("", 0, values=(port, status, service, banner))
#         self.update_dashboard()

#     def add_vulnerability(self, port, service, cve, severity, desc):
#         self.vuln_tree.insert("", 0, values=(port, service, cve, severity, desc))

#     def update_dashboard(self):
#         open_ports = sum(1 for child in self.tree.get_children()
#                          if self.tree.item(child)["values"][1] == "Open")
#         closed_ports = sum(1 for child in self.tree.get_children()
#                            if self.tree.item(child)["values"][1] == "Closed")
#         self.stats_label.config(text=f"Open: {open_ports}, Closed: {closed_ports}")

#         self.ax.clear()
#         self.ax.pie([open_ports, closed_ports], labels=["Open", "Closed"],
#                     colors=["#00FF41", "#004400"], autopct="%1.1f%%")
#         self.canvas.draw()

#     def start_scan(self):
#         target = self.target_entry.get()
#         mode = self.mode_var.get()
#         if not target:
#             messagebox.showerror("Error", "Please enter a target")
#             return

#         if mode == "Single Port":
#             try:
#                 ports = [int(self.port_entry_single.get())]
#             except:
#                 messagebox.showerror("Error", "Invalid port")
#                 return
#         else:
#             try:
#                 start = int(self.port_entry_start.get())
#                 end = int(self.port_entry_end.get())
#                 ports = list(range(start, end + 1))
#             except:
#                 messagebox.showerror("Error", "Invalid port range")
#                 return

#         self.tree.delete(*self.tree.get_children())
#         self.vuln_tree.delete(*self.vuln_tree.get_children())
#         self.scanner.stop_flag = False
#         threading.Thread(target=self.scanner.start_scan, args=(target, ports), daemon=True).start()

#     def stop_scan(self):
#         self.scanner.stop_scan()

#     def finish_scan(self):
#         messagebox.showinfo("Done", "Scan complete.")

# # ------------------ Run App ------------------
# if __name__ == "__main__":
#     root = tk.Tk()
#     app = ScannerGUI(root)
#     root.mainloop()

# scanner_threaded_themes.py
# Threaded, theme-aware SIEM-like scanner with scan-speed controls.
# Requirements: matplotlib, requests (if you re-enable NVD calls)
# pip install matplotlib requests

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
        self.root.title("Responsive SIEM Scanner (Threaded + Themes)")
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
