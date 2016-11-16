using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace Joes.Common
{
    /// <summary>
    /// 序列化扩展
    /// </summary>
    public static class JsonExtension
    {
        /// <summary>
        /// 将对象序列化
        /// </summary>
        /// <param name="obj">指定对象</param>
        /// <param name="indented">是否包含换行和缩进，主要用于控制台或文本输出格式</param>
        /// <returns></returns>
        public static string ToJson(this object obj, bool indented = false)
        {
            if (obj == null) throw new ArgumentNullException("obj");

            var setting = new JsonSerializerSettings();

            setting.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;

            var format = Formatting.None;

            if (indented) format = Formatting.Indented;

            return JsonConvert.SerializeObject(obj, format, setting);
        }

        /// <summary>
        /// 反序列化
        /// </summary>
        /// <typeparam name="T">目标类型</typeparam>
        /// <param name="str">序列化内容</param>
        /// <returns>反序列化后的对象</returns>
        public static T JsonTo<T>(this string str)
        {
            if (string.IsNullOrEmpty(str)) throw new ArgumentNullException(str);

            return JsonConvert.DeserializeObject<T>(str);
        }

        /// <summary>
        /// 反序列化
        /// </summary>
        /// <param name="str">序列化内容</param>
        /// <returns>反序列化后的动态类型对象</returns>
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

        /// <summary>
        /// 将序列化内容格式化展示
        /// </summary>
        /// <param name="str">序列化内容</param>
        /// <returns></returns>
        public static string JsonFormat(this string str)
        {
            var obj = JsonConvert.DeserializeObject(str);

            return obj.ToJson(true);
        }
    }
}