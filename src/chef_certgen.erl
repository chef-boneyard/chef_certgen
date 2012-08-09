%%%-------------------------------------------------------------------
%%% @author Christopher Brown <cb@opscode.com>
%%% @author Seth Falcon <seth@opscode.com>
%%% @copyright (C) 2010-2012, Opscode, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 25 Nov 2010 by Christopher Brown <cb@opscode.com>
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%% 
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%% 
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------

-module(chef_certgen).

-export([info/0,
         info_lib/0,
         manual_start/0,
         manual_stop/0,
         rsa_generate_keypair/1,
         version/0,
         x509_make_cert/1]).

-define(FUNC_LIST, [info_lib,
                    rsa_generate_keypair,
                    x509_make_cert]).
-define(NIF_STUB, nif_stub_error(?LINE)).
-define(CHEF_CERTGEN_VSN, 101).
-define(CHEF_CERTGEN_NIF_VSN, 101).

-on_load(on_load/0).

on_load() ->
    %% FIXME: why do we need to start crypto here instead of relying
    %% on the release or user?
    ok = ensure_started(crypto),
    LibName = "chef_certgen",
    Lib = filename:join([priv_dir(), LibName]),
    erlang:load_nif(Lib, ?CHEF_CERTGEN_NIF_VSN).

info() ->
    ?FUNC_LIST.

info_lib() -> ?NIF_STUB.

manual_start() ->
    [ok, ok] = [ ensure_started(App) || App <- [crypto, chef_certgen] ],
    ok.

manual_stop() ->
    application:stop(chef_certgen).

rsa_generate_keypair(KeyLen) ->
    {ok, PemPublicKey, PemPrivateKey} = rsa_generate_key_nif(KeyLen),
    {keypair, [{public_key, PemPublicKey}, {private_key, PemPrivateKey}]}.

x509_make_cert([{signing_key, CaKeyPair}, {issuer_cert, CaCertPem},
                {newcert_public_key, GeneratedKeypair},
                Subject,
                {serial, Serial}, {expiry, Expiry}])->
    x509_make_cert_nif([{signing_key, CaKeyPair}, {issuer_cert, CaCertPem},
                        {newcert_public_key, GeneratedKeypair},
                        Subject,
                        {serial, Serial}, {expiry, Expiry}]).

version() ->
    ?CHEF_CERTGEN_VSN.


%% -----------------------------------------
%% internal functions
%% -----------------------------------------

rsa_generate_key_nif(_KeyLen) ->
    ?NIF_STUB.

x509_make_cert_nif([{signing_key, _CaKeyPair}, {issuer_cert, _CaCertPem},
                    {newcert_public_key, _GeneratedKeypair},
                    _Subject,
                    {serial, _Serial}, {expiry, _Expiry}]) ->
    ?NIF_STUB.

ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok
    end.

priv_dir() ->
    case code:priv_dir(chef_certgen) of
        {error, bad_name} ->
            %% we are not in OTP application context
            filename:join([filename:dirname(code:which(?MODULE)), "..", "priv"]);
        Path when is_list(Path) ->
            Path
    end.

nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded,module,?MODULE,line,Line}).

