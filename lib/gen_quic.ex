defmodule GenQuic do
  @moduledoc """
  An Elixir wrapper for the Erlang gen_quic library.
  """

  def start() do
    :gen_quic.start()
  end

  @doc """
  Attempts to connect a client's socket to a server.
  """
  def connect(ip, port, options, timeout) do
    :gen_quic.connect(ip, port, options, timeout)
  end

  def connect(ip, port, options) do
    :gen_quic.connect(ip, port, options)
  end

  def listen(port, options) do
    :gen_quic.listen(port, options)
  end

  def accept(lsocket) do
    :gen_quic.accept(lsocket)
  end

  def accept(lsocket, timeout) do
    :gen_quic.accept(lsocket, timeout)
  end

  def open(socket, options) do
    :gen_quic.open(socket, options)
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
