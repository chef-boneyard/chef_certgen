# Chef Certificate Generator (chef_certgen)

Chef Certificate Generator is an Erlang NIF that exposes some of the OpenSSL functionality missing from the builtin Erlang crypto application.

# Installation and Usage

1. Install Erlang R15B01 and rebar
2. Compile and test:

  ```
  cd chef_certgen
  make
  ```

3. Test it out

  ```
  erl -pa ebin application:start(crypto). chef_certgen:rsa_generate_keypair(2048).
  ```

## Notes

### Generate a self-signed CA cert for testing

1. Create the keypair:

  ```
  openssl genrsa -out server_key.pem 2048
  ```

2. Create the cert:

  ```
  openssl req \
  -x509 -nodes -days 3650 \
  -subj '/C=US/ST=Washington/L=Seattle/CN=chef.is.awesome' \
  -new -key server_key.pem -out server_cert.pem
  ```

## Contributing

For information on contributing to this project see <https://github.com/chef/chef/blob/master/CONTRIBUTING.md>

## License

- Copyright:: 2011-2016 Chef Software, Inc.
- License:: Apache License, Version 2.0

```text
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
