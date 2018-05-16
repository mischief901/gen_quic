defmodule GenQuic do
  @moduledoc """
  An Elixir wrapper for the Erlang gen_quic library.
  """

  @doc """
  Opens a QUIC socket on the given port.
  """
  def open(port) do
    :gen_quic.open(port)
  end

  @doc """
  Opens a QUIC socket on the given port with the given options.
  """
  def open(port, options) do
    :gen_quic.open(port, options)
  end

  @doc """
  Attempts to connect a client's socket to a server.
  """
  def connect(socket, ip, port, options) do
    :gen_quic.connect(socket, ip, port, options)
  end
  
end
