defmodule GenQuicTest do
  use ExUnit.Case
  doctest GenQuic

  test "Accept" do
    GenQuic.start()
    {:ok, port} = GenQuic.listen(4000, [])
    GenQuic.accept(port)
  end

  test "Connect" do
    GenQuic.start()
    GenQuic.connect({0, 0, 0, 0}, 4000, [])
  end

  test "No Tests yet." do
    assert False
  end
end
