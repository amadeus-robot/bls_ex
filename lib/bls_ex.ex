defmodule BlsEx do
  @moduledoc """
  BlsEx provides utility to leverage BLS signatures

  BLS scheme supports aggregation of public keys and aggregation of signatures.

  Here an full example of aggregated signature verification

      iex> seed = :crypto.hash(:sha512, "myseed")
      iex> public_key1 = BlsEx.get_public_key!(seed)
      iex> signature1 = BlsEx.sign!(seed, "hello")
      iex> seed2 = :crypto.hash(:sha512, "myseed2")
      iex> public_key2 = BlsEx.get_public_key!(seed2)
      iex> signature2 = BlsEx.sign!(seed2, "hello")
      iex> aggregated_signature = BlsEx.aggregate_signatures!([signature1, signature2], [public_key1, public_key2])
      iex> aggregated_public_key = BlsEx.aggregate_public_keys!([public_key1, public_key2])
      iex> BlsEx.verify_signature?(aggregated_public_key, "hello", aggregated_signature)
      true
  """

  # 64 bytes
  @type secret_key :: <<_::512>>
  # 96 bytes
  @type signature :: <<_::768>>
  # 48 bytes
  @type public_key :: <<_::384>>

  alias __MODULE__.Native

  @doc """
  Generate a public key from a secret key
  """
  @spec get_public_key(secret_key :: secret_key()) ::
          {:ok, public_key()} | {:error, :invalid_seed}
  def get_public_key(secret_key) when is_binary(secret_key) and byte_size(secret_key) == 64,
    do: Native.get_public_key(secret_key)

  @doc """
  Same as `get_public_key/1` but raise the error
  """
  @spec get_public_key!(secret_key :: secret_key()) :: public_key()
  def get_public_key!(secret_key) do
    case get_public_key(secret_key) do
      {:ok, public_key} -> public_key
      {:error, :invalid_seed} -> raise "Invalid seed"
    end
  end

  @doc """
  Sign a message using the given secret key
  """
  @spec sign(secret_key :: secret_key(), message :: binary(), dst :: binary()) :: {:ok, signature()} | {:error, :invalid_seed}
  def sign(secret_key, data, dst)
      when is_binary(secret_key) and byte_size(secret_key) == 64 and is_binary(data) and is_binary(dst),
      do: Native.sign(secret_key, data, dst)

  @doc """
  Same as `sign/2` but raise the error
  """
  @spec sign!(secret_key :: secret_key(), message :: binary(), dst :: binary()) :: signature()
  def sign!(secret_key, data, dst) do
    case sign(secret_key, data, dst) do
      {:ok, public_key} -> public_key
      {:error, :invalid_seed} -> raise "Invalid seed"
    end
  end

  @doc """
  Verifies a single BLS signature
  """
  @spec verify?(
          public_key :: public_key(),
          signature :: signature(),
          message :: binary(),
          dst :: binary()
        ) ::
          boolean()
  def verify?(public_key, signature, message, dst)
      when is_binary(public_key) and byte_size(public_key) == 48 and is_binary(message) and is_binary(dst) and
             is_binary(signature) and byte_size(signature) == 96 do
    case Native.verify(public_key, signature, message, dst) do
      {:ok, valid?} -> valid?
      {:error, _} -> false
    end
  end

  @doc """
  Aggregate a list of signatures
  """
  @spec aggregate_signatures(signatures :: list(signature())) ::
          {:ok, aggregated_signature :: signature()} | {:error, :no_valid_keys_or_signatures}
  def aggregate_signatures(signatures) when is_list(signatures) and length(signatures) > 0 do
    case Native.aggregate_signatures(signatures) do
      {:ok, signature} -> {:ok, signature}
      {:error, :zero_size_input} -> {:error, :no_valid_keys_or_signatures}
    end
  end

  @doc """
  Same as `aggregate_signatures/2` but raise the error
  """
  @spec aggregate_signatures!(signatures :: list(signature())) :: aggregated_signature :: signature()
  def aggregate_signatures!(signatures) do
    case aggregate_signatures(signatures) do
      {:ok, signature} -> signature
      {:error, :no_valid_keys_or_signatures} -> raise "No valid public keys or signatures"
    end
  end

  @doc """
  Aggregate a list of public keys
  """
  @spec aggregate_public_keys(public_keys :: list(public_key())) :: {:ok, aggregated_public_key :: public_key()} | {:error, :no_valid_keys}
  def aggregate_public_keys(public_keys) when is_list(public_keys) and length(public_keys) > 0 do
    case Native.aggregate_public_keys(public_keys) do
      {:ok, public_key} -> {:ok, public_key}
      {:error, :zero_size_input} -> {:error, :no_valid_keys}
    end
  end

  @doc """
  Same as `aggregate_public_keys/1` but raise the error
  """
  @spec aggregate_public_keys!(public_keys :: list(public_key())) :: aggregated_public_key :: public_key()
  def aggregate_public_keys!(public_keys) do
    case aggregate_public_keys(public_keys) do
      {:ok, public_key} -> public_key
      {:error, :no_valid_keys} -> raise "No valid public keys"
    end
  end

  @doc """
  Generate a shared secret from a peer public key and secret key
  """
  @spec get_shared_secret(peer_public_key :: public_key(), secret_key :: secret_key()) ::
          {:ok, secret_key()} | {:error, :invalid_seed}
  def get_shared_secret(peer_public_key, secret_key)
    when is_binary(peer_public_key) and byte_size(peer_public_key) == 48
    and is_binary(secret_key) and byte_size(secret_key) == 64,
    do: Native.get_shared_secret(peer_public_key, secret_key)

  @doc """
  Same as `get_shared_secret/2` but raise the error
  """
  @spec get_shared_secret!(peer_public_key :: public_key(), secret_key :: secret_key()) :: secret_key :: secret_key()
  def get_shared_secret!(peer_public_key, secret_key) do
    case get_shared_secret(peer_public_key, secret_key) do
      {:ok, shared_key} -> shared_key
      {:error, :no_valid_keys} -> raise "No valid shared secret"
    end
  end
end
