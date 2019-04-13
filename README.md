# Programming Assignment 2 - Secure File Transfer

## Instructions to Run
### Prerequisite
Java is required to run the program.

### Running the Program
Before running the programs, you need to make the following changes to the static variables. They can be found at the top of each program. 

#### Running the Server (both CP-1 and CP-2):
- Change the static variables `privateKeyPath` and `serverCertPath` to the absolute paths of your private key file (.der file) and server certificate file (.crt file) accordingly. For our project, the private key file is named `example.org.der` while the server certificate file is named `example.org.crt`. 

#### Running the Client (both CP-1 and CP-2):
- Change the static variables `filename` and `filepath` to the absolute file name and file path of the file you wish to transfer respectively.
- Change the static variable `CACSEcrtpath` to the absolute path of the CA’s certificate (in our project, it is named as `cacse.crt`)
- Lastly, change the static variable `serverAddress` to the IP address of the computer running the server program (use `“localhost”` if you are running both on the same machine) 

For both protocols, run the server program before running the client program. Upon successful file transfer, the file will be transferred to the server and can be found at the same directory. 


