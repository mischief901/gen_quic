defmodule GenQuicTest do
  use ExUnit.Case
  doctest GenQuic

  test "greets the world" do
    assert GenQuic.hello() == :world
  end
end
