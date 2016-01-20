%% Copyright (c) 2013-2015, Liangjingyang <simple.continue@gmail.com>

%% tcp_client进程调用

-module(tcp_client_callback).

-behaviour(tcp_client_behaviour).

-export([
         start/1,
         handle_info/2,
         terminate/2,
         router/2,
         decode/1,
         encode/1
        ]).

-record(cb_state, {
          router,
          socket,

          id = 0,
          accname = undefined,
          p_pid = undefined,

          c_ip,
          c_port
         }).

start(Socket) ->
    case inet:peername(Socket) of
        {ok, {Ip, Port}} ->
            #cb_state{
               socket = Socket,
               c_ip = Ip,
               c_port = Port};
        _ ->
            login_lost(ip_error),
            #cb_state{socket = Socket}
    end.

handle_info(_Request, CBState) ->
    CBState.

router(CBState, Data) ->
    io:format("~nrecv ==== ~n"),
    io:format(" ip: ~w~n", [CBState#cb_state.c_ip]),
    io:format(" port: ~w~n", [CBState#cb_state.c_port]),
    io:format(" router data: ~p~n", [Data]),
    io:format("--------- ~n"),
    case Data of
        undefined ->
            login_lost("decode err");
        Data ->
            login_lost(normal)
    end,
    gen_tcp:send(CBState#cb_state.socket, <<"729">>),
    CBState.

encode(Data) ->
    Data.

decode(Binary) ->
    case Binary of
        %SSL Client Hello
        <<22:8, _V1:8, _V2:8, _L1:16, 1:8, _/binary>> ->
            decode_ssl(Binary);
        Binary ->
            io:format("decode binary: ~w~n", [Binary]),
            decode_http(Binary)
    end.

terminate(_Reason, _CBState) ->
    ok.

login_lost(Reason) ->
    self() ! {stop, Reason}.

decode_ssl(Binary) ->
    <<_ContentType:8, _ProtocolVersion:16, _Len:16, _SubType:8, _SubLen:24, _SubProtocolVersion:16, _Random:256, Binary2/binary>> = Binary,
    % session
    <<SessionIdLen:8, BeforeSessionId/binary>> = Binary2,
    <<_SessionId:SessionIdLen, AfterSessionId/binary>> = BeforeSessionId,
    % CipherSuite
    <<CipherSuiteLen:16, BeforeCipherSuite/binary>> = AfterSessionId,
    CipherSuiteLen2 = CipherSuiteLen*8,
    <<_CipherSuite:CipherSuiteLen2, AfterCipherSuite/binary>> = BeforeCipherSuite,
    % CompressionMethod
    <<CompressionMethodLen:8, BeforeCompressionMethod/binary>> = AfterCipherSuite,
    CompressionMethodLen2 = CompressionMethodLen*8,
    <<_CompressionMethod:CompressionMethodLen2, AfterCompressionMethod/binary>> = BeforeCompressionMethod,
    %% Extensions
    io:format("before extensions ~w~n", [AfterCompressionMethod]),
    <<_ExtensionsLen:16, BeforeExtensions/binary>> = AfterCompressionMethod,
    decode_ssl_extension(BeforeExtensions).

decode_ssl_extension(<<0:16, ServerNameListLen:16, ServerNameListExtension/binary>>) ->
    ServerNameListLen2 = ServerNameListLen*8,
    <<ServerNameList:ServerNameListLen2/bitstring, _/binary>> = ServerNameListExtension,
    io:format("servername list extension len: ~w, ServerNameList: ~p~n", [ServerNameListLen, ServerNameList]),
    decode_ssl_extension_server_name(ServerNameList);
decode_ssl_extension(<<_ExtensionType:16, OtherExtensionData/binary>>) ->
    <<OtherExtensionLen:16, BeforeOtherExtension/binary>> = OtherExtensionData,
    io:format("other extensions type: ~w, len: ~w~n", [_ExtensionType, OtherExtensionLen]),
    OtherExtensionLen2 = OtherExtensionLen*8,
    <<_:OtherExtensionLen2, AfterOtherExtension/binary>> = BeforeOtherExtension,
    decode_ssl_extension(AfterOtherExtension);
decode_ssl_extension(_NoMatchBinary) ->
    io:format("ssl extensions no matches ~n", []),
    undefined.

decode_ssl_extension_server_name(<<_:16, 0:8, ServerNameLen:16, ServerNameExtension/binary>>) ->
    ServerNameLen2 = ServerNameLen*8,
    <<ServerName:ServerNameLen2/bitstring, _/binary>> = ServerNameExtension,
    io:format("server name extension len: ~w, server_name: ~w~n", [ServerNameLen, ServerName]),
    ServerName;
decode_ssl_extension_server_name(_Binary) ->
    io:format("server name no matches ~n", []),
    undefined.

decode_http(Binary) ->
    SplitList = binary:split(Binary, <<"\r\n">>, [trim, global]),
    decode_http_host(SplitList).

decode_http_host([]) ->
    undefined;
decode_http_host([<<"Host: ", Host/binary>>|_]) ->
    Host;
decode_http_host([_H|T]) ->
    decode_http_host(T).
