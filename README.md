# Research & Code for a Cryptographically Secure Departmental Resource Server
## by Chris Watson (2190594w)

### Outline

### Installation
It is assumed that before continuing with installation of this code, you have downloaded, built and installed the OpenABE library from https://github.com/zeutro/openabe. This project relies on OpenABE for all cryptographic processes and so cannot operate without this library.  

A guide for this installation is not provided as part of this project, as Zeutro LLC has provided proper, up-to-date instructions within their ([repo](https://github.com/zeutro/openabe)).  

Since this project is built with Python, it is also necessary to configure, build and install the Python bindings for OpenABE (PyOpenABE) located within the OpenABE repo ([here](https://github.com/zeutro/openabe/tree/master/bindings/python)).  

After the OpenABE library has been installed and successfully passed the provided tests, the Python bindings should also be tested on the relevant tests and you should check that they can be properly imported into a Python terminal.  

Before running the servers, an instance of MongoDB (https://www.mongodb.com/download-center/community) should be up and running with two databases, titled `ResourceServer` and `UserServer`.  

The `ResourceServer` database also requires a collection titled `resource_meta` and the `UserServer` requires a collection titled `users`.  

Setting up the databases and collections is easiest from a GUI client, such as robo3T (https://robomongo.org/) or MongoDB Compass (https://www.mongodb.com/download-center/compass). But completing this step is up to the user, as the MongoDB docs, provide plenty of information on this process (https://docs.mongodb.com/).  

Both collections may be empty, the servers will configure them on launch. To start the MongoDB system, run:
  `mongod`  

Once both the library and the bindings are correctly installed, you may wish to create virtualenvs in each of the 3 server files (explained further below) before installing the required Python packages with pip:  
  `. venv/bin/activate`  
  `pip install -r requirements.txt`  
Then pip will need to install the PyOpenABE bindings into the virtualenvs, with:  
  `pip install path/to/openabe/bindings/python`  
Lastly, since the servers run on flask, two environment variables should be set in your terminal:  
  `export FLASK_APP=server.py`  
  `export FLASK_ENV=development`  
Then, the servers can each be ran for development with:  
  `flask run --port 5000` - mk_server  
  `flask run --port 5001` - res_server  
  `flask run --port 5002` - crs_server  

ALL servers must be running for the product to work properly.  

### Code
Within the /Code directory there are three 'servers' that work with each other to simulate a possible environment in with the Resource Server would be set up.

1. Master Key Server (`mk_server`)  
A private and protected server that is tasked with distributing User Keys. Contains the Master Private Key and Master Public Key used to sign all User Keys. The Master Public Key is required by other services in order to encrypt and decrypt resources, however the Master Private Key is to remain absolutely secret to the `mk_server` and should not be shared.

2. Resource Server (`res_server`)  
A 'dumb' server that simply stores the encrypted resources that are uploaded to it. It is never aware of the contents of any of the resources and only ever sends and receives ciphertext binaries. This server also stores a copy of the current Master Public Key so as to allow for distribution to end users. Otherwise its only functions are to store files uploaded by users and to send requested files to users. The Resource Server may also implement an ABAC system for determining if a user should be able to access certain files, however this is not necessary for security, as the files are inherently protected with encryption.

3. Client Resource Server (`crs_server`)  
A local server that can be ran on a user's machine to communicate with the Resource Server on the behalf of the end user. This in effect, wraps the encryption and decryption processes (as well as upload, download, search) in a simple web GUI. Allowing an end user to simply view a list of files and click to download the files they wish to view. The Client Resource Server will in fact handle the downloading and then decrypting of said file automatically for the user (assuming their User Key has the correct attributes for successful decryption).
