# PrivacyNet: Privacy Network

PrivacyNet is an anonymization tool that configures iptables and Tor to route all services, traffic and DNS through the Tor network. This tool allows users to route internet traffic through Tor and hide their real IP address.
## Features

- Installing and removing iptables rules
- Connecting to the Tor network to get its IP address and geolocate it
- Changing circuit with a new IP
- Automatic IP change at a specified interval
- Fast and easy to use

## Installation
```
git clone https://github.com/HalilDeniz/PrivacyNet.git` 
```
## Requirements

Before you can use PrivacyNet, you need to make sure that you have the necessary requirements installed. You can install these requirements by running the following command:

```
pip install -r requirements.txt
```

## Install Tor 

Before you can use PrivacyNet, first you need to install the tor package:

```
apt-get clean
apt-get update
apt-get upgrade 
apt-get install tor
```
## Getting Started

Run the following command to use the tool::

```
python3 privacynet.py
```

### Options

- `-l` or `--load`: Tor installs iptables rules.
- `-f` or `--flush`: Flushes the iptables rules to default.
- `-r` or `--refresh`: Changes the circuit and gets a new IP.
- `-i` or `--ip`: Displays the current public IP address.

## Use Cases

You can use the tool as follows:

```
python3 privacynet.py -l
 [+] Anonymizer status [ON]
 [*] Getting public IP, please wait...
 [?] Still waiting for IP address...
 [+] Your IP is {ip adresi}
 [+] Country: {Country}
 [+] City: {city}
 
 ************* OR *************
 
 python3 privacynet.py -a -t 30
 [*] Getting public IP, please wait...
 [+] Your IP is 109.70.100.82
 [+] Country: Austria
 [+] City: Vienna
 [*] IP changed successfully

 [*] Getting public IP, please wait...
 [+] Your IP is 192.42.116.176
 [+] Country: Netherlands
 [+] City: Amsterdam
 [*] IP changed successfully

 [*] Getting public IP, please wait...
 [+] Your IP is 45.154.98.28
 [+] Country: Netherlands
 [+] City: Oude Meer
 [*] IP changed successfully
.
.
.
.


```

## Contributing
Contributions are welcome! To contribute to PrivacyNet, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Open a pull request in the main repository.


## Contact

If you have any questions, comments, or suggestions about PrivacyNet, please feel free to contact me:

- LinkedIn: [LinkedIn](https://www.linkedin.com/in/halil-ibrahim-deniz/)
- TryHackMe: [TryHackMe](https://tryhackme.com/p/halilovic)
- Instagram: [Instagram](https://www.instagram.com/deniz.halil333/)
- YouTube: [YouTube](https://www.youtube.com/c/HalilDeniz)
- Email: halildeniz313@gmail.com

## About the Original Author

PrivacyNet is a fork of the original tool called toriptables2, which was created by [Rupe](https://github.com/ruped24). Rupe developed the initial version of the tool two years ago. However, the original tool was written in Python 2.7 and is no longer compatible with the latest versions. Therefore, this forked version, PrivacyNet, has been updated and modified to work with Python 3.
I would like to express my gratitude to Rupe for the inspiration and foundation provided by the original tool. Without his work, this updated version would not have been possible.
If you would like to learn more about the original tool, you can visit the [toriptables2 repository](https://github.com/ruped24/toriptables2).


## License
PrivacyNet is released under the MIT License. See LICENSE for more information.
