defmodule BlsEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :bls_ex,
      version: "0.1.3",
      elixir: "~> 1.14",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: "BLS signature utility for Elixir",
      deps: deps(),
      package: package()
    ]
  end

  defp package do
    [
      files: [
        "lib",
        "native/bls/.cargo",
        "native/bls/src",
        "native/bls/Cargo*",
        "mix.exs"
      ],
      licenses: ["AGPL-3.0-or-later"],
      links: %{"GitHub" => "https://github.com/archethic-foundation/bls_ex"}
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:test]},
      {:ex_doc, "~> 0.34.1", only: :dev, runtime: false},
      {:benchee, "~> 1.3", only: :test},
      {:rustler, ">= 0.0.0", optional: true},
      {:rustler_precompiled, "~> 0.4"}
    ]
  end
end
