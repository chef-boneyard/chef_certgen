# Chef Certificate Generator (chef_certgen) #

Chef Certificate Generator is an Erlang NIF that exposes some of the
OpenSSL functionality missing from the builtin Erlang crypto application.

# INSTALLING AND RUNNING #

1. Install Erlang R15B01 and rebar
2. Compile and test:
   
       cd chef_certgen
       make
       
3. Test it out

    erl -pa ebin
    application:start(crypto).
    chef_certgen:rsa_generate_keypair(2048).

## NOTES ##

### Generate a self-signed CA cert for testing ###

1. Create the keypair:

       openssl genrsa -out server_key.pem 2048

2. Create the cert:

        openssl req \
          -x509 -nodes -days 3650 \
          -subj '/C=US/ST=Washington/L=Seattle/CN=chef.is.awesome' \
          -new -key server_key.pem -out server_cert.pem

# CONTRIBUTING #

Send us pull requests!

# AUTHORS #

* Christopher Brown <cb@opscode.com>
* Seth Falcon <seth@opscode.com>


# LICENSE #

Apache License, Version 2.0.

