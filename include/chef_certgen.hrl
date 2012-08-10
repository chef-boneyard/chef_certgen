%%-------------------------------------------------------------------
%% @author Seth Falcon <seth@opscode.com>
%% @copyright 2012, Opscode, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%%-------------------------------------------------------------------

-record(rsa_key_pair, {
          public_key :: binary(),
          private_key :: binary()
         }).

-record(x509_subject, {
          'CN' :: string(),
          'O'  :: string(),
          'OU' :: string(),
          'C'  :: string(),
          'ST' :: string(),
          'L'  :: string()
         }).

-record(x509_input, {
          signing_key :: #rsa_key_pair{},
          issuer_cert :: binary(),
          newcert_public_key :: #rsa_key_pair{}, % FIXME: should just be pub key here
          subject :: #x509_subject{},
          serial :: non_neg_integer(),
          expiry :: non_neg_integer()
         }).
