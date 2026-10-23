defmodule ElixirApp do
  # Fixture: sweet_xml is used via its module.
  import SweetXml

  def title(xml), do: xml |> xpath(~x"//title/text()"s)
end
