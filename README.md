# BFTB | SEC P2 Submission

## Authors

**Group G22**

| Number | Name              | User                                  | Email                                    |
| -------|-------------------|---------------------------------------|------------------------------------------|
| 93581  | Francisco Bento   | <https://github.com/FranciscoBentoGit>| <francisco.bento@tecnico.ulisboa.pt>     |
| 93588  | João P. Lopes     | <https://github.com/Joao-Pedro-Lopes> | <joaopedrolopes00@tecnico.ulisboa.pt>    |
| 93584  | João A. Lopes     | <https://github.com/joao99lopes>      | <joao.costa.lopes@tecnico.ulisboa.pt>    |


## Getting Started
The goal of this project is to develop a highly dependable banking system with Byzantine Fault Tolerant guarantees, thefore the name BFT Banking.
The overall system is composed by 4 modules, **ClientApp**, **Library**(who translates requests from client),**ServerApp** and **KeyStoreService**, used to generate the Public Key Infrastructure for both sides(client and server).


### Pre-requisites

Java Developer Kit 11 is required running on Linux, Windows or Mac.
Maven 3 is also required.

To confirm that you have them installed, open a terminal and type:

```
javac -version

mvn -version
```

### Running Manually

* To compile and install all modules, run the following command under the directory *your_path*/BFTB:
```
mvn clean install -DskipTests
```
* After installing, open 2 new terminal Windows in order to setup (4Replicas/**X**Clients/KeyStoreInfrastructure).

* On Terminal Window #1:
```
mvn compile exec:java -Dexec.mainClass="pt.tecnico.ulisboa.bftb.KeyStoreService"
```
This will allow to create a Public Key Infrastructure for both clients and server, each located *your_path*/BFTB/client-files and *your_path*/BFTB/server-files. Each directory will contain a file that holds a KeyStore instance from where clients/server retrieve their private information and a file that contains all known Public Keys.

* On Terminal Window #2
  * Open 4 tabs and in each type:
```
mvn compile exec:java -Dexec.mainClass="pt.tecnico.ulisboa.bftb.server.ServerApp"
```
This simulates a replica starting up. Start up each replica with a different port from **5000** to **5003**(inclusive) so each client can connect to all replicas using different sockets.

* On Terminal Window #3:
  * Open **X** tabs and in each type:
```
mvn compile exec:java -Dexec.mainClass="pt.tecnico.ulisboa.bftb.client.ClientApp"
```
This simulates a client communicating with the server, where each client will have to authenticate himself by accessing the private KeyStore with his password and only after that being able to interact with the server.
To access a specific key pair, the password will be "secret**X**", where **X** is the key pair number selected previously.
To interact simultaneously with multiple clients, all we need is to open more terminals under the same directory.

**Manual test example:**
Assuming you already did the previous steps and let's test how the system handles a faulty replica(replica dying).
In the client's terminal, choose the key pair number 3 and proceed to type "secret3" in order to get his private key (there are 10 key pairs in total). Then open an account under his public key. On another client tab, login another client with the key pair number 7 and open his account too.
Now from client 3 send a transaction by selecting the number 7 as the receiver and choose a specific amount to send. By checking client 7 account, you will see that he has a pending transaction to be accepted.
Use Control+C on one of the replicas and use client 3 again and check client 7 account to see if the system still replies correctly. Hopefully the pending transaction will show up as previously.
You can also see that the system outputs which one of the replica is byzantine.

### Running Tests

Before running the following command, just make sure to delete the file logs inside the server-files directory, to make sure all tests start with the server clean.
```
mvn clean install
```
This is all we need to run the tests automatically.
Tests can be found inside the directory *your_path*/BFTB/src/test/java/pt/tecnico/ulisboa/bftb/.