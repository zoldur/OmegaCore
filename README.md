# Omega Core Coin
Shell script to install an [Omega Core Coin Masternode](http://omegacoin.network/) on a Linux server running Ubuntu 16.04. Use it on your own risk.  

***
## Installation:  

wget -q https://raw.githubusercontent.com/zoldur/OmegaCore/master/omegacore_install.sh  
bash omegacore_install.sh
***

## Desktop wallet setup  

After the MN is up and running, you need to configure the desktop wallet accordingly. Here are the steps for Windows Wallet
1. Open the Omega Coin Desktop Wallet.  
2. Go to RECEIVE and create a New Address: **MN1**  
3. Send **1000** OMEGA to **MN1**.  
4. Wait for 15 confirmations.  
5. Go to **Tools -> "Debug console - Console"**  
6. Type the following command: **masternode outputs**  
7. Edit **%APPDATA%\OmegaCoinCore\masternode.conf** file  
8. Add the following entry:  
```
Alias Address Privkey TxHash Output_index  
```
* Alias: **MN1**  
* Address: **VPS_IP:PORT**  
* Privkey: **Masternode Private Key**  
* TxHash: **First value from Step 6**  
* Output index:  **Second value from Step 6**  
9. Save and close the file.  
10. Go to **Masternode Tab**. If you tab is not shown, please enable it from: **Settings - Options - Wallet - Show Masternodes Tab**  
11. Click **Update status** to see your node. If it is not shown, close the wallet and start it again.  
10. Click **Start All**  

***


## Usage:  

For security reasons **OmegaCore** is installed under **omega** user, hence you need to **su - omega** before checking:    

```
OMEGA_USER=omega #replace omega with the MN username you want to check

su - $OMEGA_USER  
omegacoin-cli mnsync status  
omgecoin-cli getinfo  
```  

Also, if you want to check/start/stop **OmegaCore** , run one of the following commands as **root**:

```
OMEGA_USER=omega  #replace omega with the MN username you want to check  

systemctl status $OMEGA_USER #To check the service is running.  
systemctl start $OMEGA_USER #To start Omega service.  
systemctl stop $OMEGA_USER #To stop Omega service.  
systemctl is-enabled $OMEGA_USER #To check whetether Omega service is enabled on boot or not.  
```  

***

## Known issues:
1. It doesn't work with NATed IP. Or at least I didn't have enough time/use cases to make it work.

***

  
Any donation is highly appreciated  

**OMEGA**: oS12fYXouxKYVZuDaYWTx4UAaxLwjXNmqj  
**BTC**: 1BzeQ12m4zYaQKqysGNVbQv1taN7qgS8gY  
**ETH**: 0x39d10fe57611c564abc255ffd7e984dc97e9bd6d  
**LTC**: LXrWbfeejNQRmRvtzB6Te8yns93Tu3evGf  

