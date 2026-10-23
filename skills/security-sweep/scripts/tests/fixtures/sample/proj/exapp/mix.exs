defmodule Exapp.MixProject do
  use Mix.Project
  def project, do: [app: :exapp, version: "0.1.0", deps: [{:decimal, "~> 2.0"}]]
end
