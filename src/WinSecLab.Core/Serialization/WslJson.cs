using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSecLab.Core.Serialization;

/// <summary>把 KeyValuePair 序列化成 ["name","value"] 两元数组，比 {"Key":..,"Value":..} 更适合放进报告。</summary>
public sealed class KeyValuePairConverter : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType &&
        typeToConvert.GetGenericTypeDefinition() == typeof(KeyValuePair<,>);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        var args = typeToConvert.GetGenericArguments();
        var converterType = typeof(KvpConverter<,>).MakeGenericType(args[0], args[1]);
        return (JsonConverter)Activator.CreateInstance(converterType)!;
    }

    private sealed class KvpConverter<TKey, TValue> : JsonConverter<KeyValuePair<TKey, TValue>>
    {
        public override KeyValuePair<TKey, TValue> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                TKey? key = default;
                TValue? value = default;
                while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                {
                    var prop = reader.GetString();
                    reader.Read();
                    if (string.Equals(prop, "Key", StringComparison.OrdinalIgnoreCase))
                        key = JsonSerializer.Deserialize<TKey>(ref reader, options);
                    else if (string.Equals(prop, "Value", StringComparison.OrdinalIgnoreCase))
                        value = JsonSerializer.Deserialize<TValue>(ref reader, options);
                    else
                        reader.Skip();
                }
                return new KeyValuePair<TKey, TValue>(key!, value!);
            }

            if (reader.TokenType != JsonTokenType.StartArray)
                throw new JsonException("期望数组或对象形式的键值对。");

            reader.Read();
            var k = JsonSerializer.Deserialize<TKey>(ref reader, options);
            reader.Read();
            var v = JsonSerializer.Deserialize<TValue>(ref reader, options);
            reader.Read();
            return new KeyValuePair<TKey, TValue>(k!, v!);
        }

        public override void Write(Utf8JsonWriter writer, KeyValuePair<TKey, TValue> value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            JsonSerializer.Serialize(writer, value.Key, options);
            JsonSerializer.Serialize(writer, value.Value, options);
            writer.WriteEndArray();
        }
    }
}

/// <summary>全局统一的 JSON 配置，保证落盘、UI 与报告三处一致。</summary>
public static class WslJson
{
    public static readonly JsonSerializerOptions Storage = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(), new KeyValuePairConverter() },
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(), new KeyValuePairConverter() },
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Serialize<T>(T value, bool indented = false) =>
        JsonSerializer.Serialize(value, indented ? Pretty : Storage);

    public static T? Deserialize<T>(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return default;
        try
        {
            return JsonSerializer.Deserialize<T>(json, Storage);
        }
        catch (JsonException)
        {
            return default;
        }
    }
}
