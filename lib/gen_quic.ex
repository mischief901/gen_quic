defmodule GenQuic do
  @moduledoc """
  An Elixir wrapper for the Erlang gen_quic library.
  """

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

  def listen(port, options) do
    :gen_quic.listen(port, options)
  end

  def accept(lsocket, timeout) do
    :gen_quic.accept(lsocket, timeout)
  end

  def close(socket) do
    :gen_quic.close(socket)
  end

  def send(socket, data) do
    :gen_quic.send(socket, data)
  end

  def recv(socket, length) do
    :gen_quic.recv(socket, length)
  end

  def recv(socket, length, timeout) do
    :gen_quic.recv(socket, length, timeout)
  end

  def controlling_process(socket, pid) do
    :gen_quic.controlling_process(socket, pid)
  end
  
end
