%% Copyright (c) 2013-2015, Liangjingyang <simple.continue@gmail.com>

-module(tcp_listener_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, {{one_for_all, 10, 10}, []}}.

