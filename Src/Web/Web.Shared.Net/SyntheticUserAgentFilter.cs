﻿namespace Microsoft.ApplicationInsights.Web
{
    using System;
    using System.Text.RegularExpressions;
    using Implementation;
    using Microsoft.ApplicationInsights.Extensibility.Implementation.Tracing;

    /// <summary>
    /// Allows configuration of patterns for synthetic traffic filters.
    /// </summary>
    public class SyntheticUserAgentFilter
    {
        private string pattern;

        /// <summary>
        /// Initializes a new instance of the <see cref="SyntheticUserAgentFilter"/> class.
        /// </summary>
        public SyntheticUserAgentFilter()
        {
        }

        /// <summary>
        /// Gets or sets the regular expression pattern applied to the user agent string to determine whether traffic is synthetic.
        /// </summary>
        public string Pattern
        {
            get
            {
                return this.pattern;
            }

            set
            {
                this.pattern = value;

                try
                {
                    this.RegularExpression = new Regex(this.pattern, RegexOptions.Compiled);
                }
                catch (ArgumentException ex)
                {
                    WebEventSource.Log.SyntheticUserAgentTelemetryInitializerRegularExpressionParsingException(ex.ToInvariantString());
                }                
            }
        }

        /// <summary>
        /// Gets or sets the readable name for the synthetic traffic source. If not provided, defaults to the pattern match.
        /// </summary>
        public string SourceName { get; set; }

        internal Regex RegularExpression { get; set; }
    }
}
