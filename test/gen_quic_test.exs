defmodule GenQuicTest do
  use ExUnit.Case, async: true
  doctest GenQuic

  
  setup_all do
    GenQuic.start()
  end

  test "Accept Timeout" do
    {:ok, lport} = GenQuic.listen(4000, [])
    {time, result} = :timer.tc(fn -> GenQuic.accept(lport, 100) end, [])
    assert result == {:error, :timeout}
    ## Timeout is received within 10% of value. (Need to check this math)
    diff = time / 100000
    assert diff < 1.1
  end
  
  @tag timeout: 3000
  test "Accept" do
    accept_port = accept()
    assert is_port(accept_port)
  end

  defp accept do
    with {:ok, lport} <- GenQuic.listen(4000, []),
         {:ok, port} <- GenQuic.accept(lport) do
      port
    end
  end

  test "Connect Timeout" do
    {time, result} = :timer.tc(fn -> GenQuic.connect({0, 0, 0, 0}, 4000, [], 100) end, [])
    assert result == {:error, :timeout}
    ## Same as above, Timeout is received within 10%.
    diff = time / 100000
    assert diff < 1.1
  end
  
  @tag timeout: 3000
  test "Connect" do
    port = connect()
    assert is_port(port)
  end

  defp connect do
    with {:ok, port} <- GenQuic.connect({0, 0, 0, 0}, 4000, []) do
      port
    end
  end
  
  test "No Tests yet." do
    assert False
  end
end
