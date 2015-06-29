json.array!(@messages) do |message|
  json.extract! message, :id, :sender, :message
  json.url message_url(message, format: :json)
end
