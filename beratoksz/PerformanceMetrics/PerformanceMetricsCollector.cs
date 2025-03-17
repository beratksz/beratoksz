using System.Collections.Concurrent;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace beratoksz.PerformanceMetrics
{
    public static class PerformanceMetricsCollector
    {
        private static ConcurrentBag<long> _requestDurations = new ConcurrentBag<long>();
        private static readonly object _lock = new object();

        public static void AddRequestDuration(long duration)
        {
            lock (_lock)
            {
                _requestDurations.Add(duration);
            }
        }

        public static (double average, long min, long max, int count) GetMetrics()
        {
            lock (_lock)
            {
                var durations = _requestDurations.ToArray();
                if (durations.Length == 0)
                {
                    return (0, 0, 0, 0);
                }

                double average = durations.Average();
                long min = durations.Min();
                long max = durations.Max();
                int count = durations.Length;

                return (average, min, max, count);
            }
        }
    }
}
