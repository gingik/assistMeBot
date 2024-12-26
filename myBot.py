import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import requests
import json
import os
import base64
import fitz  # PDF HANDLING
import time
import urllib.robotparser
import aiohttp
import asyncio
import logging
import subprocess
import platform
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import shutil  # For checking command availability
import datetime 
from queue import Queue
import threading

class ChatApp:
    def __init__(self):
        self.setup_logging()
        
        # Validate dependencies before initializing
        self.validate_dependencies()
        
        # Tkinter setup
        self.root = tk.Tk()
        self.root.title("Ollama Chat")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize variables with error handling
        try:
            self.current_model = self.get_default_model()
        except Exception as e:
            logging.error(f"Failed to set default model: {e}")
            self.current_model = "llama3.2"
        
        self.uploaded_files = []
        self.analyzed_content = ""
        self.scanning = False
        # Setup UI components
        self.create_ui()
        
        # Async setup with error handling
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            # Start Ollama server with retry logic
            self.start_ollama_server()
            
            # Load initial model with error handling
            self.load_model(self.current_model)
        except Exception as e:
            logging.error(f"Initialization error: {e}")
            messagebox.showerror("Initialization Error", str(e))
    
    def setup_logging(self):
        """Configure logging with more detailed format."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('ollama_chat.log', mode='a')
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_dependencies(self):
        """Check if required external tools are available."""
        dependencies = ['ollama', 'nmap']
        for dep in dependencies:
            if not shutil.which(dep):
                logging.warning(f"{dep.capitalize()} is not installed. Some features might be limited.")
    
    def get_default_model(self):
        """Retrieve the default Ollama model, with fallback."""
        try:
            # Query available models from Ollama
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            logging.info(f"Ollama server response: {response.text}")
            
            models = response.json().get('models', [])
            logging.info(f"Available models: {models}")
            
            if not models:
                logging.warning("No models found, using fallback")
                return "llama3.2"
                
            # Filter out vision models unless specifically requested
            standard_models = [model['name'] for model in models 
                            if not any(vision_name in model['name'].lower() 
                                    for vision_name in ['vision', 'image', 'visual'])]
            
            if standard_models:
                chosen_model = standard_models[0]
                logging.info(f"Selected model: {chosen_model}")
                return chosen_model
            
            # If no standard models found, use first available
            chosen_model = models[0]['name']
            logging.info(f"No standard models found, using: {chosen_model}")
            return chosen_model
            
        except Exception as e:
            logging.warning(f"Could not retrieve models: {e}")
            return "llama3.2"
    
    def create_ui(self):
        """Create the UI components for the chat application."""
        # Create main container frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Top frame for model selection and buttons
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=5)

        # Model selection dropdown
        self.model_var = tk.StringVar(value=self.current_model)
        model_label = ttk.Label(top_frame, text="Model:")
        model_label.pack(side=tk.LEFT, padx=5)
        
        self.model_combo = ttk.Combobox(top_frame, textvariable=self.model_var)
        self.model_combo['values'] = ('llama3.2', 'llama3.2-vision', 'mistral')
        self.model_combo.pack(side=tk.LEFT, padx=5)
        self.model_combo.bind('<<ComboboxSelected>>', self.on_model_change)

        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            available_models = [model['name'] for model in response.json().get('models', [])]
            logging.info(f"Setting combobox values to: {available_models}")
            self.model_combo['values'] = available_models if available_models else ('llama2', 'codellama', 'mistral')
        except Exception as e:
            logging.warning(f"Could not get models for dropdown: {e}")
            self.model_combo['values'] = ('llama2', 'codellama', 'mistral')
        # Clear chat button
        clear_btn = ttk.Button(top_frame, text="Clear Chat", command=self.clear_chat)
        clear_btn.pack(side=tk.RIGHT, padx=5)

        # System prompt frame
        system_frame = ttk.LabelFrame(main_frame, text="System Prompt")
        system_frame.pack(fill=tk.X, pady=5)
        
        self.system_prompt = tk.Text(system_frame, height=3, wrap=tk.WORD)
        self.system_prompt.pack(fill=tk.X, padx=5, pady=5)
        self.system_prompt.insert("1.0", "You are an expert software developer specializing in Python and JavaScript...")

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=20)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=5)
        self.chat_display.configure(state='disabled')

        # File upload frame
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        upload_btn = ttk.Button(file_frame, text="Upload Files", command=self.upload_files)
        upload_btn.pack(side=tk.LEFT, padx=5)
        
        analyze_btn = ttk.Button(file_frame, text="Analyze Files", command=self.analyze_uploaded_files)
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        self.file_label = ttk.Label(file_frame, text="No files selected")
        self.file_label.pack(side=tk.LEFT, padx=5)

        # URL analysis frame
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=5)
        
        url_label = ttk.Label(url_frame, text="URL:")
        url_label.pack(side=tk.LEFT, padx=5)
        
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        analyze_url_btn = ttk.Button(url_frame, text="Analyze URL", command=self.analyze_url_wrapper)
        analyze_url_btn.pack(side=tk.LEFT, padx=5)

        # Network scan button (if available)
        if self.network_scan_available():
            scan_btn = ttk.Button(url_frame, text="Scan Network", command=self.scan_network)
            scan_btn.pack(side=tk.LEFT, padx=5)

        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.input_field = tk.Text(input_frame, height=3, wrap=tk.WORD)
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.stop_btn = ttk.Button(input_frame, text="Stop", command=self.stop_response, state='disabled')
        self.stop_btn.pack(side=tk.RIGHT, padx=5)
        
        send_btn = ttk.Button(input_frame, text="Send", command=self.send_message)
        send_btn.pack(side=tk.RIGHT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        # Progress bar is initially hidden, will be shown when needed
    
    def start_ollama_server(self, max_retries=3):
        """Start Ollama server with robust error handling and retry logic."""
        for attempt in range(max_retries):
            try:
                response = requests.get("http://localhost:11434/api/tags", timeout=5)
                if response.status_code == 200:
                    logging.info("Ollama server is running.")
                    return
            except requests.RequestException:
                logging.info(f"Attempting to start Ollama server (Attempt {attempt + 1})")
                try:
                    subprocess.Popen(
                        ["ollama", "serve"], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                    time.sleep(3)  # Wait for server startup
                except Exception as e:
                    logging.error(f"Failed to start Ollama server: {e}")
        
        raise RuntimeError("Could not start or connect to Ollama server")
    
    def load_model(self, model_name):
        """More robust model loading with comprehensive error handling."""
        try:
            # Verify model exists
            tags_response = requests.get("http://localhost:11434/api/tags", timeout=5)
            available_models = [model['name'] for model in tags_response.json().get('models', [])]
            
            if model_name not in available_models:
                logging.warning(f"Model {model_name} not found. Available models: {available_models}")
                model_name = available_models[0] if available_models else "llama3.2"
            
            # Stop current model if different
            if self.current_model != model_name:
                subprocess.run(
                    ["ollama", "stop", self.current_model], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL,
                    check=False
                )
            
            # Pull and run the model
            subprocess.run(
                ["ollama", "pull", model_name],
                capture_output=True,
                text=True,
                check=True
            )
            subprocess.run(
                ["ollama", "run", model_name], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                check=True
            )
            
            self.current_model = model_name
            logging.info(f"Successfully loaded model: {model_name}")
        
        except subprocess.CalledProcessError as e:
            logging.error(f"Model loading failed: {e}")
            messagebox.showerror("Model Loading Error", str(e))
        except Exception as e:
            logging.error(f"Unexpected error in model loading: {e}")
            messagebox.showerror("Unexpected Error", str(e))
    
    def switch_model(self):
        """Enhanced model switching with more robust error handling."""
        selected = self.model_var.get()
        try:
            self.load_model(selected)
            self.update_chat_display(f"\nModel switched to: {self.current_model}")
        except Exception as e:
            logging.error(f"Model switch failed: {e}")
            messagebox.showerror("Model Switch Error", str(e))
    
    def network_scan_available(self):
        """Check if network scanning is possible."""
        return shutil.which('nmap') is not None
    
    def get_current_network(self):
        """
        Get the current network subnet in CIDR notation (e.g., 192.168.1.0/24)
        """
        try:
            if platform.system() == "Windows":
                # For Windows, use ipconfig
                output = subprocess.check_output("ipconfig", text=True)
                for line in output.split('\n'):
                    if "IPv4 Address" in line:
                        ip = line.split(": ")[1].strip()
                        # Convert IP to network address
                        ip_parts = ip.split('.')
                        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            else:
                # For Unix-like systems (Linux, macOS), use ifconfig or ip addr
                try:
                    # Try ip addr first
                    output = subprocess.check_output(["ip", "addr"], text=True)
                    for line in output.split('\n'):
                        if "inet " in line and not "127.0.0.1" in line:
                            # Extract IP address
                            ip = line.split()[1].split('/')[0]
                            ip_parts = ip.split('.')
                            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # Fallback to ifconfig for macOS
                    output = subprocess.check_output(["ifconfig"], text=True)
                    for line in output.split('\n'):
                        if "inet " in line and not "127.0.0.1" in line:
                            # Extract IP address
                            ip = line.split()[1]
                            ip_parts = ip.split('.')
                            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            raise Exception("Could not determine network address")
        
        except Exception as e:
            logging.error(f"Error getting network address: {e}")
            raise
        
    def scan_network(self):
        if self.scanning:
            self.update_chat_display("\nA scan is already in progress. Please wait...\n")
            return
            
        try:
            self.scanning = True
            self.scan_results_queue = Queue()
            
            # Disable scan button
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Button) and widget['text'] == "Scan Network":
                    widget.configure(state='disabled')

            if not shutil.which('nmap'):
                self.update_chat_display("\nError: nmap is not installed.\n")
                return

            # Start scan in background thread
            scan_thread = threading.Thread(target=self._background_scan)
            scan_thread.daemon = True
            scan_thread.start()
            
            # Start periodic UI updates
            self.root.after(100, self._check_scan_results)
            
        except Exception as e:
            self.scanning = False
            self.update_chat_display(f"\nError starting scan: {str(e)}\n")
            self._enable_scan_button()
    
    def _background_scan(self):
        try:
            current_network = self.get_current_network()
            self.scan_results_queue.put(("status", f"Scanning network: {current_network}\n"))
            
            # Use faster scan options
            nmap_discovery = subprocess.run(
                ['nmap', '-T4', '-n', '-sn', '--min-parallelism', '100', current_network],
                capture_output=True,
                text=True,
                check=True
            )
            
            devices = []
            current_device = None
            
            for line in nmap_discovery.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    ip = line.split()[-1].strip('()')
                    self.scan_results_queue.put(("device_found", f"Found device: {ip}\n"))
                    
                    # Quick port scan with optimized parameters
                    try:
                        port_scan = subprocess.run(
                            ['nmap', '-T4', '-n', '--max-retries', '1', '--top-ports', '100', 
                            '--min-parallelism', '50', ip],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        
                        open_ports = []
                        for port_line in port_scan.stdout.split('\n'):
                            if 'open' in port_line and 'tcp' in port_line:
                                port = port_line.split('/')[0]
                                service = port_line.split()[-1]
                                open_ports.append({"port": port, "service": service})
                        
                        if open_ports:
                            self.scan_results_queue.put(
                                ("ports_found", f"Found {len(open_ports)} open ports on {ip}\n")
                            )
                        
                        devices.append({
                            "ip": ip,
                            "open_ports": open_ports
                        })
                        
                    except subprocess.CalledProcessError:
                        self.scan_results_queue.put(("error", f"Port scan failed for {ip}\n"))
            
            # Send final results
            self.scan_results_queue.put(("complete", devices))
            
        except Exception as e:
            self.scan_results_queue.put(("error", str(e)))
        finally:
            self.scan_results_queue.put(("done", None))
                            
    def analyze_url_wrapper(self):
        """Wrapper to run async URL analysis in the event loop."""
        try:
            # Create new event loop if needed
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Show progress bar
            self.progress.pack(fill='x', pady=5)
            self.progress.start()
            
            # Run the analysis
            loop.run_until_complete(self.analyze_url())
            
        except Exception as e:
            error_msg = f"\nError in URL analysis wrapper: {str(e)}\n"
            logging.error(error_msg, exc_info=True)
            self.update_chat_display(error_msg)
        finally:
            # Ensure progress bar is hidden
            self.progress.stop()
            self.progress.pack_forget()
                    
    def start_ollama_server(self):
        try:
            # Try to connect to Ollama server
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code != 200:
                raise requests.ConnectionError("Ollama server not responding")
        except requests.RequestException:
            # If the server isn't running, start it
            print("Starting Ollama server...")
            subprocess.Popen(["ollama", "serve"], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL,
                             start_new_session=True)
            time.sleep(5)  # Give some time for the server to start
            self.check_server_status()
    
    def check_server_status(self):
        for _ in range(5):  # Try up to 5 times
            try:
                response = requests.get("http://localhost:11434/api/tags", timeout=5)
                if response.status_code == 200:
                    print("Ollama server is now running.")
                    return
            except requests.RequestException:
                print("Waiting for Ollama server to start...")
                time.sleep(1)  # Wait a second before next attempt
        raise Exception("Failed to start or connect to Ollama server after multiple attempts.")
                    
    def switch_model(self):
        selected = self.model_var.get()
        try:
            if self.current_model != selected:
                subprocess.run(["ollama", "stop", self.current_model], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL,
                               check=False)
                
                subprocess.run(["ollama", "run", selected], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL,
                               check=True)
                
                self.current_model = selected
                self.update_chat_display(f"\nModel switched to: {self.current_model}")
            else:
                self.update_chat_display(f"\nAlready using model: {self.current_model}")
        except Exception as e:
            self.update_chat_display(f"\nError switching model: {str(e)}")
                                
    def stop_response(self):
        # Add logic to stop response
        self.stop_btn.configure(state='disabled')
        
    def clear_files(self):
        self.uploaded_files = []
        self.file_label.config(text="No files selected")

    def upload_files(self):
        """Open file dialog and add files to upload list."""
        files = filedialog.askopenfilenames(
            filetypes=[
                ("All files", "*.*"),
                ("PDF files", "*.pdf"),
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Text files", "*.txt"),
                ("Python files", "*.py"),
                ("C++ files", "*.cpp *.h *.hpp")
            ]
        )
        if files:
            self.uploaded_files.extend(files)
            filenames = [os.path.basename(f) for f in files]
            self.file_label.config(text=f"{len(self.uploaded_files)} files selected")
            self.update_chat_display(f"\nUploaded files: {', '.join(filenames)}\n")

    def analyze_uploaded_files(self):
        if not self.uploaded_files:
            messagebox.showwarning("No Files", "Please upload files first")
            return
        
        self.analyzed_content = ""
        file_contents = []
        
        for file_path in self.uploaded_files:
            content = self.read_file(file_path)
            if content.startswith("Error"):
                self.update_chat_display(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] {content}\n")
            else:
                self.update_chat_display(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Analyzed file: {os.path.basename(file_path)}\n")
                file_contents.append(content)
        
        if file_contents:
            self.analyzed_content = "\n\n".join(file_contents)
            self.update_chat_display("\nFile analysis complete.\n")
    
    def read_file(self, file_path):
        """
        Read and return the contents of a file.
        Returns a string with either the file contents or an error message.
        """
        try:
            # Convert to absolute path and normalize
            abs_path = os.path.abspath(file_path)
            logging.info(f"Reading file: {abs_path}")
            
            # Get the file extension
            _, ext = os.path.splitext(abs_path)
            ext = ext.lower()
            
            # Handle different file types
            if ext in ['.txt', '.py', '.cpp', '.h', '.hpp', '.js', '.html', '.css']:
                try:
                    with open(abs_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                        return content
                except UnicodeDecodeError:
                    # Try with a different encoding if UTF-8 fails
                    with open(abs_path, 'r', encoding='latin-1') as file:
                        content = file.read()
                        return content
                        
            elif ext == '.pdf':
                try:
                    doc = fitz.open(abs_path)
                    content = "\n".join(page.get_text() for page in doc)
                    doc.close()
                    return content
                except Exception as e:
                    return f"Error reading PDF file: {str(e)}"
                    
            elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                return f"Image file detected: {os.path.basename(abs_path)} (binary content not shown)"
                
            else:
                return f"Unsupported file type: {ext}"
                
        except FileNotFoundError:
            return f"Error: File not found - {os.path.basename(file_path)}"
        except PermissionError:
            return f"Error: Permission denied - {os.path.basename(file_path)}"
        except Exception as e:
            return f"Error reading file {os.path.basename(file_path)}: {str(e)}"
            
    async def crawl_url(self, session, url, depth=1, visited=None, keywords=None):
        if visited is None:
            visited = set()
        if depth <= 0 or url in visited:
            logging.debug(f"URL crawl depth limit reached or URL already visited: {url}")
            return ""
        
        visited.add(url)
        content = ""

        try:
            logging.debug(f"Checking permissions to crawl {url}")
            if not self.can_fetch(url):
                logging.info(f"Crawling {url} is disallowed by robots.txt")
                return f"\nCrawling {url} is disallowed by robots.txt\n"

            logging.debug(f"Fetching content from {url}")
            async with session.get(url) as response:
                html = await response.text()
                logging.debug(f"Received response for {url}")
                soup = BeautifulSoup(html, 'html.parser')

                # Remove script and style tags to get clean text
                for script in soup(["script", "style"]):
                    script.decompose()
                text = soup.get_text()
                content += f"\nContent from {url}:\n{text[:500]}...\n"

                # Find links to crawl further
                links = soup.find_all('a', href=True)
                base_domain = urlparse(url).netloc
                prioritized_links = []

                for link in links:
                    href = link['href']
                    if href.startswith('/'):
                        href = f"https://{base_domain}{href}"
                    elif not href.startswith(('http://', 'https://')):
                        continue
                    
                    # Prioritize links based on domain or keywords in text
                    if urlparse(href).netloc == base_domain or (keywords and any(kw in link.get_text().lower() for kw in keywords)):
                        prioritized_links.append(link)

                # Crawl prioritized links if depth allows
                if depth > 1:
                    logging.debug(f"Further crawling with depth {depth - 1}")
                    tasks = []
                    for link in sorted(prioritized_links, key=lambda l: -sum(kw in l.get_text().lower() for kw in keywords))[:5]:
                        href = link['href']
                        if href.startswith('/'):
                            href = f"https://{base_domain}{href}"
                        tasks.append(asyncio.create_task(self.crawl_url(session, href, depth-1, visited, keywords)))

                    # Wait for all crawling tasks to complete
                    crawled_content = await asyncio.gather(*tasks)
                    for sub_content in crawled_content:
                        content += sub_content

                return content
        except Exception as e:
            logging.error(f"Error while crawling {url}: {str(e)}", exc_info=True)
            return f"\nError crawling {url}: {str(e)}\n"
      
    async def analyze_url(self):
        """Analyze a URL and extract content."""
        logging.info("Starting URL analysis")
        try:
            url = self.url_entry.get().strip()
            if not url:
                self.update_chat_display("\nError: Please enter a URL\n")
                return

            # Ensure URL has proper scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            self.update_chat_display(f"\nAnalyzing URL: {url}\n")
            
            # Create a new aiohttp session for each analysis
            async with aiohttp.ClientSession() as session:
                try:
                    # Set a timeout for the request
                    async with session.get(url, timeout=10) as response:
                        if response.status != 200:
                            self.update_chat_display(f"\nError: Got status code {response.status}\n")
                            return
                        
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract useful information
                        title = soup.title.string if soup.title else "No title found"
                        meta_desc = soup.find('meta', attrs={'name': 'description'})
                        description = meta_desc['content'] if meta_desc else "No description found"
                        
                        # Extract main text content (remove scripts, styles, etc)
                        for script in soup(["script", "style", "meta", "link"]):
                            script.decompose()
                        
                        text_content = soup.get_text(separator='\n', strip=True)
                        
                        # Format the analysis results
                        analysis = f"""
    URL Analysis Results:
    --------------------
    Title: {title}
    Description: {description}

    Content Preview:
    {text_content[:500]}...
    """
                        
                        self.analyzed_content = analysis
                        self.update_chat_display("\nAnalysis complete. Results added to context.\n")
                        
                except asyncio.TimeoutError:
                    self.update_chat_display("\nError: Request timed out\n")
                except aiohttp.ClientError as e:
                    self.update_chat_display(f"\nError connecting to URL: {str(e)}\n")
        
        except Exception as e:
            error_msg = f"\nError during URL analysis: {str(e)}\n"
            logging.error(error_msg, exc_info=True)
            self.update_chat_display(error_msg)
        finally:
            # Ensure progress bar is stopped and hidden
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.progress.pack_forget())
    
    def clear_chat(self):
        """Clear chat display and reset variables."""
        self.chat_display.configure(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.configure(state='disabled')
        self.analyzed_content = ""
        self.uploaded_files = []
        self.file_label.config(text="No files selected")
        self.url_entry.delete(0, tk.END)
        self.system_prompt.delete("1.0", tk.END)
        self.system_prompt.insert("1.0", "You are an expert software developer specializing in Python and JavaScript. Your knowledge spans backend development, APIs, testing, data structures, algorithms, and web development best practices. You provide clear, production-ready code examples with proper error handling and documentation. You follow PEP 8 for Python and ESLint standards for JavaScript.")

    def update_chat_display(self, message):
        """Update chat display with new messages."""
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, message)
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def send_message(self):
        message = self.input_field.get("1.0", "end-1c")
        if not message.strip():
            return
        
        self.progress.pack(fill='x', pady=5)
        self.progress.start()
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, f"\nYou: {message}\n")
        self.input_field.delete("1.0", "end")
        self.stop_btn.configure(state='normal')

        
        image_files = []
        context = []
        # Add analyzed content if it exists (from network scan or other analyses)
        if self.analyzed_content:
            context.append(self.analyzed_content)
        if context:
            message = message + "\n\nContext:\n" + "\n\n".join(context)
            
        if self.uploaded_files:
            for file_path in self.uploaded_files:
                _, ext = os.path.splitext(file_path)
                ext = ext.lower()
                try:
                    if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                        image_files.append(file_path)
                    elif ext == '.pdf':
                        doc = fitz.open(file_path)
                        content = "\n".join(page.get_text() for page in doc)
                        context.append(content)
                        doc.close()
                    else:
                        with open(file_path, 'r', encoding='utf-8') as file:
                            context.append(f"Content of {os.path.basename(file_path)}:\n{file.read()}")
                except Exception as e:
                    self.chat_display.insert(tk.END, f"\nError reading {file_path}: {str(e)}\n")
     
        try:
            system_prompt = self.system_prompt.get("1.0", "end-1c")
            request_data = {
                "model": self.current_model,
                "prompt": message,
                "system": system_prompt,
                "stream": True
            }
            
            if image_files:
                request_data["images"] = []
                for img_path in image_files:
                    with open(img_path, "rb") as image_file:
                        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                        request_data["images"].append(encoded_string)
            
            response = requests.post(
                "http://localhost:11434/api/generate",
                json=request_data,
                stream=True
            )
            
            self.chat_display.insert(tk.END, "AI: ")
            for line in response.iter_lines():
                if line:
                    try:
                        json_response = json.loads(line.decode())
                        chunk = json_response.get("response", "")
                        self.chat_display.insert(tk.END, chunk)
                        self.chat_display.see(tk.END)
                        self.root.update()
                    except json.JSONDecodeError:
                        self.chat_display.insert(tk.END, f"\nJSON Decode Error: {line}\n")
        except Exception as e:
            self.chat_display.insert(tk.END, f"\nError: {str(e)}\n")
        finally:
            self.chat_display.configure(state='disabled')
            self.stop_btn.configure(state='disabled')
            self.progress.stop()
            self.progress.pack_forget()
    
    def on_model_change(self, event):
        self.switch_model()

    def load_model(self, model_name):
        """Loads a specific model, stopping any currently running model."""
        try:
            # Stop the current model if different
            if self.current_model != model_name:
                subprocess.run(["ollama", "stop", self.current_model], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL,
                               check=True)
            # Start the new model
            subprocess.run(["ollama", "run", model_name], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL,
                           check=True)
            self.current_model = model_name
            print(f"Model loaded: {model_name}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to load model {model_name}: {e}")
    
    def can_fetch(self, url):
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(urlparse(url).scheme + "://" + urlparse(url).netloc + "/robots.txt")
        rp.read()
        return rp.can_fetch("*", url)        
    
    def _check_scan_results(self):
        """Process any available scan results and update UI"""
        try:
            while not self.scan_results_queue.empty():
                msg_type, data = self.scan_results_queue.get_nowait()
                
                if msg_type == "status":
                    self.update_chat_display(data)
                elif msg_type == "device_found":
                    self.update_chat_display(data)
                elif msg_type == "ports_found":
                    self.update_chat_display(data)
                elif msg_type == "error":
                    self.update_chat_display(f"\nError: {data}\n")
                elif msg_type == "complete":
                    self._format_and_display_results(data)
                elif msg_type == "done":
                    self.scanning = False
                    self._enable_scan_button()
                    return
                    
            # Check again in 100ms if scan still running
            if self.scanning:
                self.root.after(100, self._check_scan_results)
                
        except Exception as e:
            self.update_chat_display(f"\nError processing results: {str(e)}\n")
            self.scanning = False
            self._enable_scan_button()
    
    def _format_and_display_results(self, devices):
        """Format and display the final scan results."""
        scan_results = "\nNetwork Scan Results:\n" + "=" * 50 + "\n"
        
        for device in devices:
            scan_results += f"\nIP: {device['ip']}\n"
            if device['open_ports']:
                scan_results += "Open Ports:\n"
                for port in device['open_ports']:
                    scan_results += f"  - Port {port['port']}: {port['service']}\n"
            else:
                scan_results += "No open ports found\n"
            scan_results += "-" * 30 + "\n"
        
        self.analyzed_content += scan_results
        self.update_chat_display(scan_results)
        self.update_chat_display("\nNetwork scan completed.\n")

    def _enable_scan_button(self):
        """Re-enable the scan button."""
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Button) and widget['text'] == "Scan Network":
                widget.configure(state='normal')
                        
    def run(self):
        """Start the application main loop."""
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = ChatApp()
        app.run()
    except Exception as e:
        logging.critical(f"Unhandled exception in main: {e}", exc_info=True)
        messagebox.showerror("Critical Error", str(e))