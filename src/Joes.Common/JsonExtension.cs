using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace Joes.Common
{
    public static class JsonExtension
    {
        public static string ToJson(this object obj, bool indented = false)
        {
            if (obj == null) throw new ArgumentNullException("obj");

            var setting = new JsonSerializerSettings();

            setting.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;

            var format = Formatting.None;

            if (indented) format = Formatting.Indented;

            return JsonConvert.SerializeObject(obj, format, setting);
        }

        public static T JsonTo<T>(this string str)
        {
            if (string.IsNullOrEmpty(str)) throw new ArgumentNullException(str);

            return JsonConvert.DeserializeObject<T>(str);
        }

        public static dynamic JsonTo(this string str)
        {
            if (string.IsNullOrEmpty(str)) throw new ArgumentNullException(str);

            JContainer container;

            if (str.StartsWith("["))
            {
                container = JArray.Parse(str);
            }
            else
            {
                container = JObject.Parse(str);
            }

            dynamic result = container;

            return result;
        }

        public static string JsonFormat(this string json)
        {
            var obj = JsonConvert.DeserializeObject(json);

            return obj.ToJson(true);
        }
    }
}