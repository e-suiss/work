# T-99, MD-3, E-93
bootstrap = System.fetch_env!("LOCAL_BOOTSTRAP") |> File.read!() |> Jason.decode!()
find = fn list, key, value -> Enum.find(Map.fetch!(bootstrap, list), &(&1[key] == value)) end
access_tenant = find.("realms", "slug", "platform") |> Map.fetch!("tenant")
work_client = find.("clients", "product", "work") |> Map.fetch!("client_id")

{:ok, _started} = Application.ensure_all_started(:relay)
{:ok, system} = Relay.Actor.new(:system, "system:work_dev", "system:work_dev")
{:ok, access} = Relay.Actor.new(:access, "access", "access")
digest = fn text -> :crypto.hash(:sha256, "work-dev:" <> text) end

{:ok, _datasets} = Relay.Datasets.load_package(system)
{:ok, region} = Relay.Region.cast(System.fetch_env!("RELAY_REGION"))

tenant =
  %{
    id: Relay.Id.generate(),
    access_tenant_id: access_tenant,
    region: region,
    sector: "general",
    default_timezone: "Europe/Istanbul",
    default_locale: "tr-TR",
    record_digest: digest.(access_tenant)
  }
  |> Relay.Tenancy.Provisioning.create_tenant(system)
  |> case do
    {result, id} when result in [:created, :exists] and is_binary(id) -> id
    other -> raise "relay-register: tenant #{inspect(other)}"
  end

scope = Relay.Scope.new!(tenant, :test)
client = [Relay.Id.generate(), work_client, nil, ["publish", "read"], "work-dev", digest.(work_client)]

case Relay.Repo.in_scope(scope, fn _status ->
       Relay.Repo.call!("relay_fn.api_client_upsert", client ++ Relay.Actor.params(access))
     end) do
  {:ok, [%{"result" => result}]} when result in ["created", "updated", "unchanged"] -> :ok
  other -> raise "relay-register: API client #{inspect(other)}"
end

category = %{
  key: "work",
  name: "Work",
  message_class: "transactional",
  locked: false,
  enabled: true,
  channel_defaults: %{},
  default_expires_in: nil,
  frequency: nil,
  digest_allowed: false
}

definition = fn name ->
  %{
    "name" => name,
    "category" => "work",
    "message_class" => "transactional",
    "event_schema" => %{
      "type" => "object",
      "properties" => %{"reason" => %{"type" => "string"}},
      "required" => ["reason"]
    },
    "steps" => [
      %{"type" => "channel", "key" => "inbox", "channel" => "in_app", "template" => "work"}
    ]
  }
end

publish = fn key ->
  {:ok, {:ok, {result, version}}} =
    Relay.Repo.in_scope(scope, fn _status ->
      Relay.Workflow.request_publication(scope, key, nil, "work-dev", system)
    end)

  true = result in [:pending, :already_pending]
  {:ok, {:published, _errors}} = Relay.Workflow.run_gate(scope, version)
end

_category =
  try do
    Relay.Repo.in_scope(scope, fn _status ->
      Relay.Preferences.create_category(scope, category, system)
    end)
  rescue
    error -> {:kept, error}
  end

workflows = [
  {"work-action-required", "Work: action required"},
  {"work-information", "Work: information"}
]

for {key, name} <- workflows do
  case Relay.Workflow.resolve_published(scope, key) do
    {:ok, {:ok, _published}} ->
      :ok

    {:ok, :not_published} ->
      publish.(key)

    {:ok, :not_found} ->
      {:ok, {:ok, {:created, _id, _version}}} =
        Relay.Repo.in_scope(scope, fn _status ->
          Relay.Workflow.create(scope, key, definition.(name), system)
        end)

      publish.(key)
  end
end

IO.puts("relay-register: Work's client #{work_client} publishes in tenant #{access_tenant} (test)")
