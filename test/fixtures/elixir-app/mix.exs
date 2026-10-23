defmodule ElixirApp.MixProject do
  use Mix.Project

  def project do
    [app: :elixir_app, version: "0.1.0", elixir: "~> 1.14", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [{:sweet_xml, "0.6.6"}]
  end
end
