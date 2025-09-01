import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import subprocess
import platform
import psutil
import nmap
import scapy.all as scapy
from scapy.layers import http
import json
import datetime

class XillenNetworkToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("XILLEN Network Toolkit v2.0")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a1a')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook', background='#1a1a1a')
        self.style.configure('TFrame', background='#1a1a1a')
        self.style.configure('TButton', background='#2d2d2d', foreground='white')
        
        self.create_widgets()
        self.scan_results = {}
        
    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_network_scanner_tab(notebook)
        self.create_packet_analyzer_tab(notebook)
        self.create_device_discovery_tab(notebook)
        self.create_bandwidth_monitor_tab(notebook)
        self.create_network_mapper_tab(notebook)
        
    def create_network_scanner_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Network Scanner")
        
        ttk.Label(frame, text="XILLEN Network Scanner", font=('Arial', 16, 'bold')).pack(pady=10)
        
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame, text="Target:").pack(side='left')
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.pack(side='left', padx=5)
        self.target_entry.insert(0, "192.168.1.1")
        
        ttk.Button(input_frame, text="Quick Scan", command=self.quick_scan).pack(side='left', padx=5)
        ttk.Button(input_frame, text="Full Scan", command=self.full_scan).pack(side='left', padx=5)
        ttk.Button(input_frame, text="Service Detection", command=self.service_scan).pack(side='left', padx=5)
        
        self.scan_output = scrolledtext.ScrolledText(frame, height=20, bg='#2d2d2d', fg='#00ff00')
        self.scan_output.pack(fill='both', expand=True, padx=10, pady=5)
        
    def create_packet_analyzer_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Packet Analyzer")
        
        ttk.Label(frame, text="XILLEN Packet Analyzer", font=('Arial', 16, 'bold')).pack(pady=10)
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        ttk.Label(control_frame, text="Interface:").pack(side='left')
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, values=interfaces)
        interface_combo.pack(side='left', padx=5)
        if interfaces:
            interface_combo.set(interfaces[0])
        
        ttk.Button(control_frame, text="Start Capture", command=self.start_capture).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Save Capture", command=self.save_capture).pack(side='left', padx=5)
        
        self.packet_output = scrolledtext.ScrolledText(frame, height=20, bg='#2d2d2d', fg='#00ff00')
        self.packet_output.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.capturing = False
        self.captured_packets = []
        
    def create_device_discovery_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Device Discovery")
        
        ttk.Label(frame, text="XILLEN Device Discovery", font=('Arial', 16, 'bold')).pack(pady=10)
        
        discovery_frame = ttk.Frame(frame)
        discovery_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(discovery_frame, text="Network Range:").pack(side='left')
        self.range_entry = ttk.Entry(discovery_frame, width=20)
        self.range_entry.pack(side='left', padx=5)
        self.range_entry.insert(0, "192.168.1.0/24")
        
        ttk.Button(discovery_frame, text="Discover Devices", command=self.discover_devices).pack(side='left', padx=5)
        ttk.Button(discovery_frame, text="Export Results", command=self.export_discovery).pack(side='left', padx=5)
        
        self.discovery_tree = ttk.Treeview(frame, columns=('IP', 'MAC', 'Hostname', 'OS', 'Status'), show='headings')
        self.discovery_tree.heading('IP', text='IP Address')
        self.discovery_tree.heading('MAC', text='MAC Address')
        self.discovery_tree.heading('Hostname', text='Hostname')
        self.discovery_tree.heading('OS', text='Operating System')
        self.discovery_tree.heading('Status', text='Status')
        self.discovery_tree.pack(fill='both', expand=True, padx=10, pady=5)
        
    def create_bandwidth_monitor_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Bandwidth Monitor")
        
        ttk.Label(frame, text="XILLEN Bandwidth Monitor", font=('Arial', 16, 'bold')).pack(pady=10)
        
        monitor_frame = ttk.Frame(frame)
        monitor_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(monitor_frame, text="Start Monitoring", command=self.start_monitoring).pack(side='left', padx=5)
        ttk.Button(monitor_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side='left', padx=5)
        ttk.Button(monitor_frame, text="Reset Stats", command=self.reset_stats).pack(side='left', padx=5)
        
        stats_frame = ttk.Frame(frame)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.download_label = ttk.Label(stats_frame, text="Download: 0 KB/s")
        self.download_label.pack(side='left', padx=10)
        
        self.upload_label = ttk.Label(stats_frame, text="Upload: 0 KB/s")
        self.upload_label.pack(side='left', padx=10)
        
        self.total_label = ttk.Label(stats_frame, text="Total: 0 MB")
        self.total_label.pack(side='left', padx=10)
        
        self.bandwidth_output = scrolledtext.ScrolledText(frame, height=15, bg='#2d2d2d', fg='#00ff00')
        self.bandwidth_output.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.monitoring = False
        
    def create_network_mapper_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Network Mapper")
        
        ttk.Label(frame, text="XILLEN Network Mapper", font=('Arial', 16, 'bold')).pack(pady=10)
        
        mapper_frame = ttk.Frame(frame)
        mapper_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(mapper_frame, text="Target Network:").pack(side='left')
        self.mapper_target = ttk.Entry(mapper_frame, width=25)
        self.mapper_target.pack(side='left', padx=5)
        self.mapper_target.insert(0, "192.168.1.0/24")
        
        ttk.Button(mapper_frame, text="Generate Map", command=self.generate_map).pack(side='left', padx=5)
        ttk.Button(mapper_frame, text="Export Map", command=self.export_map).pack(side='left', padx=5)
        
        self.map_output = scrolledtext.ScrolledText(frame, height=20, bg='#2d2d2d', fg='#00ff00')
        self.map_output.pack(fill='both', expand=True, padx=10, pady=5)
        
    def get_network_interfaces(self):
        try:
            return list(psutil.net_if_addrs().keys())
        except:
            return ['eth0', 'wlan0', 'lo']
            
    def quick_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Starting quick scan of {target}...\n")
        
        def scan():
            try:
                nm = nmap.PortScanner()
                result = nm.scan(target, arguments='-sS -sV -O --top-ports 100')
                
                self.root.after(0, lambda: self.display_scan_results(result))
            except Exception as e:
                self.root.after(0, lambda: self.scan_output.insert(tk.END, f"Error: {str(e)}\n"))
                
        threading.Thread(target=scan, daemon=True).start()
        
    def full_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Starting full scan of {target}...\n")
        
        def scan():
            try:
                nm = nmap.PortScanner()
                result = nm.scan(target, arguments='-sS -sV -O -A -p-')
                
                self.root.after(0, lambda: self.display_scan_results(result))
            except Exception as e:
                self.root.after(0, lambda: self.scan_output.insert(tk.END, f"Error: {str(e)}\n"))
                
        threading.Thread(target=scan, daemon=True).start()
        
    def service_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Starting service detection on {target}...\n")
        
        def scan():
            try:
                nm = nmap.PortScanner()
                result = nm.scan(target, arguments='-sV --version-intensity 9')
                
                self.root.after(0, lambda: self.display_service_results(result))
            except Exception as e:
                self.root.after(0, lambda: self.scan_output.insert(tk.END, f"Error: {str(e)}\n"))
                
        threading.Thread(target=scan, daemon=True).start()
        
    def display_scan_results(self, result):
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, "=== XILLEN Network Scanner Results ===\n\n")
        
        for host in result['scan']:
            self.scan_output.insert(tk.END, f"Host: {host}\n")
            self.scan_output.insert(tk.END, f"State: {result['scan'][host]['status']['state']}\n")
            
            if 'osmatch' in result['scan'][host]:
                for os in result['scan'][host]['osmatch']:
                    self.scan_output.insert(tk.END, f"OS: {os['name']} (Accuracy: {os['accuracy']}%)\n")
                    
            if 'tcp' in result['scan'][host]:
                self.scan_output.insert(tk.END, "\nOpen Ports:\n")
                for port in result['scan'][host]['tcp']:
                    service = result['scan'][host]['tcp'][port]
                    self.scan_output.insert(tk.END, f"  {port}/tcp - {service['name']} - {service['product']} {service['version']}\n")
                    
            self.scan_output.insert(tk.END, "\n" + "="*50 + "\n\n")
            
    def display_service_results(self, result):
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, "=== XILLEN Service Detection Results ===\n\n")
        
        for host in result['scan']:
            self.scan_output.insert(tk.END, f"Host: {host}\n")
            
            if 'tcp' in result['scan'][host]:
                self.scan_output.insert(tk.END, "\nServices:\n")
                for port in result['scan'][host]['tcp']:
                    service = result['scan'][host]['tcp'][port]
                    self.scan_output.insert(tk.END, f"  Port {port}:\n")
                    self.scan_output.insert(tk.END, f"    Service: {service['name']}\n")
                    self.scan_output.insert(tk.END, f"    Product: {service['product']}\n")
                    self.scan_output.insert(tk.END, f"    Version: {service['version']}\n")
                    self.scan_output.insert(tk.END, f"    Extra: {service['extrainfo']}\n\n")
                    
    def start_capture(self):
        if self.capturing:
            return
            
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return
            
        self.capturing = True
        self.captured_packets = []
        self.packet_output.delete(1.0, tk.END)
        self.packet_output.insert(tk.END, f"Starting packet capture on {interface}...\n")
        
        def capture():
            try:
                scapy.sniff(iface=interface, prn=self.packet_callback, store=0)
            except Exception as e:
                self.root.after(0, lambda: self.packet_output.insert(tk.END, f"Capture error: {str(e)}\n"))
                
        threading.Thread(target=capture, daemon=True).start()
        
    def stop_capture(self):
        self.capturing = False
        self.packet_output.insert(tk.END, "Packet capture stopped.\n")
        
    def packet_callback(self, packet):
        if not self.capturing:
            return
            
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            info = f"[{timestamp}] HTTP Request: {http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}\n"
        elif packet.haslayer(scapy.TCP):
            tcp_layer = packet.getlayer(scapy.TCP)
            info = f"[{timestamp}] TCP: {packet[scapy.IP].src}:{tcp_layer.sport} -> {packet[scapy.IP].dst}:{tcp_layer.dport} [{tcp_layer.flags}]\n"
        elif packet.haslayer(scapy.UDP):
            udp_layer = packet.getlayer(scapy.UDP)
            info = f"[{timestamp}] UDP: {packet[scapy.IP].src}:{udp_layer.sport} -> {packet[scapy.IP].dst}:{udp_layer.dport}\n"
        elif packet.haslayer(scapy.ICMP):
            info = f"[{timestamp}] ICMP: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}\n"
        else:
            info = f"[{timestamp}] Packet: {packet.summary()}\n"
            
        self.captured_packets.append(info)
        self.root.after(0, lambda: self.packet_output.insert(tk.END, info))
        
    def save_capture(self):
        if not self.captured_packets:
            messagebox.showinfo("Info", "No packets captured")
            return
            
        filename = f"xillen_capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.write("=== XILLEN Packet Capture ===\n\n")
                for packet in self.captured_packets:
                    f.write(packet)
            messagebox.showinfo("Success", f"Capture saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {str(e)}")
            
    def discover_devices(self):
        network_range = self.range_entry.get()
        if not network_range:
            messagebox.showerror("Error", "Please enter network range")
            return
            
        for item in self.discovery_tree.get_children():
            self.discovery_tree.delete(item)
            
        def discover():
            try:
                nm = nmap.PortScanner()
                result = nm.scan(network_range, arguments='-sn')
                
                self.root.after(0, lambda: self.display_discovery_results(result))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Discovery failed: {str(e)}"))
                
        threading.Thread(target=discover, daemon=True).start()
        
    def display_discovery_results(self, result):
        for host in result['scan']:
            if result['scan'][host]['status']['state'] == 'up':
                ip = host
                mac = result['scan'][host]['addresses'].get('mac', 'Unknown')
                hostname = result['scan'][host]['hostnames'][0]['name'] if result['scan'][host]['hostnames'] else 'Unknown'
                os = 'Unknown'
                status = 'Online'
                
                self.discovery_tree.insert('', 'end', values=(ip, mac, hostname, os, status))
                
    def export_discovery(self):
        items = self.discovery_tree.get_children()
        if not items:
            messagebox.showinfo("Info", "No devices to export")
            return
            
        filename = f"xillen_devices_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            data = []
            for item in items:
                values = self.discovery_tree.item(item)['values']
                data.append({
                    'ip': values[0],
                    'mac': values[1],
                    'hostname': values[2],
                    'os': values[3],
                    'status': values[4]
                })
                
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Success", f"Devices exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            
    def start_monitoring(self):
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_start_time = datetime.datetime.now()
        self.last_bytes_sent = psutil.net_io_counters().bytes_sent
        self.last_bytes_recv = psutil.net_io_counters().bytes_recv
        
        def monitor():
            while self.monitoring:
                try:
                    current_stats = psutil.net_io_counters()
                    
                    bytes_sent = current_stats.bytes_sent - self.last_bytes_sent
                    bytes_recv = current_stats.bytes_recv - self.last_bytes_recv
                    
                    download_speed = bytes_recv / 1024
                    upload_speed = bytes_sent / 1024
                    
                    total_download = current_stats.bytes_recv / (1024 * 1024)
                    total_upload = current_stats.bytes_sent / (1024 * 1024)
                    
                    self.root.after(0, lambda: self.update_bandwidth_stats(download_speed, upload_speed, total_download, total_upload))
                    
                    self.last_bytes_sent = current_stats.bytes_sent
                    self.last_bytes_recv = current_stats.bytes_recv
                    
                    import time
                    time.sleep(1)
                except:
                    break
                    
        threading.Thread(target=monitor, daemon=True).start()
        
    def stop_monitoring(self):
        self.monitoring = False
        
    def reset_stats(self):
        self.monitor_start_time = datetime.datetime.now()
        self.last_bytes_sent = psutil.net_io_counters().bytes_sent
        self.last_bytes_recv = psutil.net_io_counters().bytes_recv
        
    def update_bandwidth_stats(self, download, upload, total_down, total_up):
        self.download_label.config(text=f"Download: {download:.1f} KB/s")
        self.upload_label.config(text=f"Upload: {upload:.1f} KB/s")
        self.total_label.config(text=f"Total: {total_down:.1f} MB ↓ / {total_up:.1f} MB ↑")
        
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.bandwidth_output.insert(tk.END, f"[{timestamp}] ↓ {download:.1f} KB/s | ↑ {upload:.1f} KB/s\n")
        self.bandwidth_output.see(tk.END)
        
    def generate_map(self):
        network = self.mapper_target.get()
        if not network:
            messagebox.showerror("Error", "Please enter target network")
            return
            
        self.map_output.delete(1.0, tk.END)
        self.map_output.insert(tk.END, f"Generating network map for {network}...\n")
        
        def map_network():
            try:
                nm = nmap.PortScanner()
                result = nm.scan(network, arguments='-sn -PR -PS22,80,443 -PA21,23,80,3389')
                
                self.root.after(0, lambda: self.display_network_map(result))
            except Exception as e:
                self.root.after(0, lambda: self.map_output.insert(tk.END, f"Mapping error: {str(e)}\n"))
                
        threading.Thread(target=map_network, daemon=True).start()
        
    def display_network_map(self, result):
        self.map_output.delete(1.0, tk.END)
        self.map_output.insert(tk.END, "=== XILLEN Network Map ===\n\n")
        
        online_hosts = []
        for host in result['scan']:
            if result['scan'][host]['status']['state'] == 'up':
                online_hosts.append(host)
                
        self.map_output.insert(tk.END, f"Network: {self.mapper_target.get()}\n")
        self.map_output.insert(tk.END, f"Online hosts: {len(online_hosts)}\n\n")
        
        for i, host in enumerate(online_hosts, 1):
            self.map_output.insert(tk.END, f"{i}. {host} [ONLINE]\n")
            
        self.map_output.insert(tk.END, "\n" + "="*50 + "\n")
        
    def export_map(self):
        network = self.mapper_target.get()
        if not network:
            messagebox.showerror("Error", "Please generate a map first")
            return
            
        filename = f"xillen_network_map_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.write(self.map_output.get(1.0, tk.END))
            messagebox.showinfo("Success", f"Network map exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = XillenNetworkToolkit(root)
    root.mainloop()

