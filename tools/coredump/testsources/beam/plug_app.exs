#! /usr/bin/env elixir

# To run:
# ERL_FLAGS="+JPperf true" elixir --no-halt plug_app.exs

Mix.install([:bandit, :plug, :finch])

defmodule MyApp.Application do
  use Application

  def start(_type, _args) do
    children = [
      {Bandit, plug: MyApp.Router},
      {Finch, name: MyApp.Finch},
      MyApp.Worker
    ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

defmodule MyApp.Router do
  use Plug.Router

  plug :match
  plug :dispatch

  get "/hello" do
    send_resp(conn, 200, "world")
  end

  match _ do
    send_resp(conn, 404, "oops")
  end
end

defmodule MyApp.Worker do
  use GenServer

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  def init(opts \\ []) do
    Process.send_after(self(), :work, 100)
    {:ok, opts}
  end

  def handle_info(:work, state) do
    send(self(), :work)
    Task.async_stream(1..16, fn _i ->
      Finch.build(:get, "http://localhost:4000/hello") |> Finch.request(MyApp.Finch)
    end) |> Enum.to_list()
    {:noreply, state}
  end
end

{:ok, pid} = MyApp.Application.start(:permanent, nil)
Process.unlink(pid)
