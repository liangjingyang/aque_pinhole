%% Copyright (c) 2013-2015, Liangjingyang <simple.continue@gmail.com>

%% tcp_client进程调用

-module(tcp_client_behaviour).

-callback start(Socket::port()) -> CBState::tuple().

-callback handle_info(Resquest::term(), CBState::tuple()) -> CBState2::tuple().

-callback terminate(Reason::term(), CBState::tuple()) -> ok.

-callback router(CBState::tuple(), Data::term()) -> CBState2::tuple().

-callback decode(Any::any()) -> Term::term().

-callback encode(Term::term()) -> Any::any().


