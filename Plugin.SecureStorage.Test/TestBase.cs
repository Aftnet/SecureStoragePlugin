﻿using Plugin.SecureStorage.Abstractions;
using Xunit;

namespace Plugin.SecureStorage.Test
{
    public abstract class TestBase
    {
        protected abstract ISecureStorage GetTarget();

        private readonly ISecureStorage Target;

        public TestBase()
        {
            Target = GetTarget();
        }

        [Fact]
        public void Works()
        {
            string TestKey = nameof(TestKey);
            string TestKey2 = nameof(TestKey2);
            string TestValue = nameof(TestValue);

            var readValue = Target.GetValue(TestKey);
            Assert.Null(readValue);

            Target.SetValue(TestKey, TestValue);
            readValue = Target.GetValue(TestKey);
            Assert.Equal(TestValue, readValue);

            readValue = Target.GetValue(TestKey2);
            Assert.Null(readValue);

            Target.DeleteKey(TestKey);
            readValue = Target.GetValue(TestKey);
            Assert.Null(readValue);
        }
    }
}
