# Install LiteWork

**Linux (just download, nothing to build)**

```
tar -xzf litework-*-linux-x86_64-static.tar.gz
sudo mv litework-*/litework /usr/local/bin/
litework --help
```

**Any OS (build it yourself)**

```
curl https://sh.rustup.rs -sSf | sh      # installs Rust (Windows: run rustup-init.exe from rustup.rs)
cargo install --path crates/litework
litework --help
```

**Run it**

```
litework capture.pcap     # open a pcap
sudo litework -i eth0     # live on an interface (Linux)
```
