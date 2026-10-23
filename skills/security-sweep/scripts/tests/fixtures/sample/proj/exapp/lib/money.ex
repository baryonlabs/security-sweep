defmodule Exapp.Money do
  def round_to(value, places), do: Decimal.round(value, places)
end
