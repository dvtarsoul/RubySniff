# 🌐 RubySniff

RubySniff is an advanced network packet sniffer written in Ruby, designed to capture and analyze packets on a specified network interface. This tool provides detailed information about the packets, including source and destination MAC and IP addresses, protocols, ports, and packet lengths. The captured data is displayed in a user-friendly tabular format and can be saved to a file.

## 🔍 Features

- Capture and analyze network packets on a specified interface
- Filter packets using Berkeley Packet Filter (BPF) syntax
- Display detailed packet information, including MAC and IP addresses, protocols, ports, and lengths
- Save captured packets to a specified file
- Verbose mode for real-time packet display
- Interactive CLI with colorized output and progress spinner

## 📀 Requirements

- Ruby (>= 2.5)
- `pcaprub` gem
- `colorize` gem
- `terminal-table` gem
- `tty-prompt` gem
- `tty-spinner` gem

## 🔌 Installation

1. Install Ruby if you haven't already. You can download it from [ruby-lang.org](https://www.ruby-lang.org/en/downloads/).
2. Install the required gems:

    ```bash
    gem install pcaprub colorize terminal-table tty-prompt tty-spinner
    ```

3. Clone this repository:

    ```bash
    git clone https://github.com/dvtarsoul/RubySniff
    cd RubySniff
    ```

## 💻 Usage

Run the sniffer with the following command:

```bash
sudo ruby rubysniff.rb -i INTERFACE -f FILTER -o OUTPUT_FILE [-v]
```

### 💡 Options

- `-i, --interface INTERFACE` : Network interface to sniff (required)
- `-f, --filter FILTER` : BPF filter string (optional)
- `-o, --output FILE` : Output file for captured packets (required)
- `-v, --verbose` : Run in verbose mode (optional)

### 📝 Examples

1. Capture all TCP packets on the `wlan0` interface and save to `output.txt`:

    ```bash
    sudo ruby rubysniff.rb -i wlan0 -f "tcp" -o output.txt
    ```

2. Capture all packets on the `eth0` interface and display them in real-time:

    ```bash
    sudo ruby rubysniff.rb -i eth0 -o output.txt -v
    ```

## 💫 Acknowledgments

- This project uses the [pcaprub](https://github.com/pcaprub/pcaprub) library for packet capture.
- Thanks to the creators of the `colorize`, `terminal-table`, `tty-prompt`, and `tty-spinner` gems for their excellent tools.

## 💿 **Credits**
 - tarsoul
 - pcaprub

## ⚠️ Disclaimer

```
All tools and projects are created for educational purposes and ethical hacking. Please use responsibly. I'm not responsible of your acts.