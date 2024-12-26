# Ollama Chat Application

A Python-based desktop chat application that interfaces with Ollama for local LLM interactions, featuring network scanning and file analysis capabilities.

## Technical Documentation

### Core Components

#### ChatApp Class
Main application class handling UI and core functionality:
- Model management with Ollama
- File analysis and upload
- Network scanning with nmap
- URL analysis and crawling
- Asynchronous operations handling

### Key Features

1. **Model Management**
- Dynamic model switching
- Automatic Ollama server startup
- Support for multiple model types (standard and vision models)
- Streaming response handling

2. **Network Scanning**
- Threaded scanning implementation
- Real-time progress updates
- Port discovery and service identification
- Configurable scan parameters
- Queue-based result handling

3. **File Analysis**
- Support for multiple file types (PDF, text, code files)
- Encoding detection and handling
- Error handling for file operations
- Progress tracking

4. **URL Analysis**
- Asynchronous web crawling
- Robots.txt compliance
- Content extraction and parsing
- Depth-limited crawling

### Technical Implementation Details

#### Threading Model
- Main UI thread for interface
- Background thread for network scanning
- Async operations for URL analysis
- Queue-based communication between threads

#### Error Handling
- Comprehensive exception catching
- Logging system integration
- User feedback through UI
- Graceful degradation of features

#### Performance Optimizations
- Parallel network scanning
- Efficient file reading
- Progressive UI updates
- Resource cleanup

---

# README.md

# Ollama Chat

A desktop chat application that combines local LLM capabilities with system analysis tools.

## Features

- 💬 Chat interface with Ollama LLM models
- 🔍 Network scanning capabilities
- 📁 File analysis and processing
- 🌐 URL analysis and content extraction
- 🖼️ Vision model support

## Prerequisites

- Python 3.8+
- Ollama installed and configured
- nmap (for network scanning)

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ollama-chat.git

# Install dependencies
pip install -r requirements.txt

# Install system dependencies
# For macOS:
brew install ollama nmap

# For Linux:
sudo apt-get install ollama nmap
```

## Usage

```bash
python myBot.py
```

## Configuration

Default configuration can be modified in the UI:
- Model selection
- System prompt
- Scan parameters

## Dependencies

- tkinter: UI framework
- aiohttp: Async HTTP operations
- BeautifulSoup4: Web parsing
- PyMuPDF: PDF processing
- requests: HTTP client
- nmap: Network scanning

## Contributing

1. Fork the repository
2. Create your feature branch
3. Submit a pull request

## License

MIT License
