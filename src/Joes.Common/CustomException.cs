using System;

namespace Joes.Common
{
    /// <summary>
    /// 自定义异常
    /// </summary>
    public class CustomException : Exception
    {
        /// <summary>
        /// 默认初始化
        /// </summary>
        public CustomException() : base() { }

        /// <summary>
        /// 使用异常信息进行初始化
        /// </summary>
        /// <param name="message">异常信息</param>
        public CustomException(string message) : base(message) { }

        /// <summary>
        /// 使用异常信息进行初始化
        /// </summary>
        /// <param name="message">异常信息</param>
        /// <param name="innerException">原始异常</param>
        public CustomException(string message, Exception innerException) : base(message, innerException) { }
    }
}