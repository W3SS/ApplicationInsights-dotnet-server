# Changelog

## Version 2.6.0-beta2
- [Added a max length restriction to values passed in through requests.](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/810)


## Version 2.6.0-beta1
- [Fix: Dependency Telemetry is not collected with DiagnosticSource when response does not have content.](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/739)
- [Expose Request-Context in Access-Control-Expose-Headers header, and that allows cross-component correlation between AJAX dependencies and server-side requests.](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/802)
- [Improve DependencyCollectorEventSource.Log.CurrentActivityIsNull](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/799)
- A significant number of upgrades to our testing infrastructure.
- Add Azure Instance Metadata information to heartbeat properties in WindowsServer package (full framework only). [Completes issue #666 from -dotnet repo](https://github.com/Microsoft/ApplicationInsights-dotnet/issues/666)


## Version 2.5.0
- [Fix: System.InvalidCastException for SQL Dependency](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/782)


## Version 2.5.0-beta2
- [Fix: When debugging netcoreapp2.0 in VS, http dependencies are tracked twice](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/723)
- [Fix: DependencyCollector check if exits before add](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/724)
- [Track requests and dependencies from ServiceBus .NET Client (Microsoft.Azure.ServiceBus 3.0.0](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/740)
- [Fix: REST API Request filter bug](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/175)
- [Fix: SyntheticUserAgentTelemetryInitializer null check](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/750)
- [Track dependencies from EventHubs .NET Client (Microsoft.Azure.EventHubs 1.1.0)](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/753)

**Project**
- [Moved common files to Shared projects](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/730)
- [Stabilizing QuickPulse tests](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/736)
- [Make local debug of DependencyCollector functional tests easier](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/738)
- [More DependencyCollector tests](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/741)
- [Increase max timeout for QuickPulse tests](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/744)
- [Increase tests codecoverage](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/745)
- [More DependencyCollector functional tests](https://github.com/Microsoft/ApplicationInsights-dotnet-server/pull/746)


## Version 2.5.0-beta1
- Removed `net40` targets from all packages. Use the version 2.4 of SDK if your application is still compiled with the framework 4.0.
- Adds ADO SQL dependency collection for SqlClient (System.Data.SqlClient) on .NET Core versions 1.0 and 2.0.
- /ping calls to Live Metrics Stream (aka QuickPulse) now contain the invariant version of the agent.
- [Fix App Id Lookup bug](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/683)
- [Fix DiagnosticsListener should have safe OnNext](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/649)
- [Fix PerfCounterCollector module may go into endless loop (ASP.NET Core on Full Framework)](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/678)
- [Fix Start Timestamp is not set for Http dependency telemetry in dotnet core 2.0](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/658)
- [Support collecting non-HTTP dependency calls from 3rd party libraries](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/665)
- Bugfix for CorrelationIdLookup NullRef Ex
- [Added Test App for testing DependencyCollector on .NET Core 2.0](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/572)

**Project**
- install.ps1 is now signed
- increase max allowed runtime of functional tests
- fix for "project system has encountered an error"


## Version 2.4.1
- [Hotfix to address the issue where DependencyCollection breaks Azure Storage Emulator calls](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/640)

## Version 2.4.0
- Updated version of DiagnosticSource to 4.4.0

## Version 2.4.0-beta5
- Updated version of DiagnosticSource referenced.

## Version 2.4.0-beta4
- Bug fixes.

## Version 2.4.0-beta3
- Exceptions statistics feature is not enabled by default
- [Parse AppId from HTTP response headers when dependency collection is facilitated with Http Desktop DiagnosticSource](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/509)
- [Fix double correlation header injection with latest DiagnosticSource](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/530)
- `DisableDiagnosticSourceInstrumentation` configuration flag was added to `DependencyTrackingTelemetryModule`.
  * By default `DisableDiagnosticSourceInstrumentation` is set to false, this enables correlation of telemetry items and [application map](http://aka.ms/AiAppMapPreview) in multi-tier applications.
  * When `DisableDiagnosticSourceInstrumentation` is set to true (so that the instrumentation is off)
    * correlation between requests, dependencies, and other telemetry items is limited,
    * telemetry correlation between multiple services involved in the operation processing is not possible,
    * and the cross-component correlation feature and application map experience is limited.
  * **Note**: this configuration option has no effect for applications that run in an Azure Web Application with the [ApplicationInsights site extension](https://docs.microsoft.com/en-us/azure/application-insights/app-insights-azure-web-apps) or have [runtime instrumentation](https://github.com/Microsoft/ApplicationInsights-Home/tree/master/Samples/AzureEmailService/WorkerRoleA#report-dependencies).
- [Fix memory leak in Dependency collector](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/554)

## Version 2.4.0-beta2
- [Handle breaking changes from DiagnosticSource](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/480)
- [Exceptions statistics metrics uses `.Context.Operation.Name` instead of custom property `operationName`](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/394)
- [Separate event source names for Web and Dependency Modules to fix the bug](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/508)
- [Fix DependencyCollector memory leak on netcoreapp1.1 and prior](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/514)

## Version 2.4.0-beta1
- Report status code for the dependencies failed with non-protocol issue like DNS resolution or SSL shakeup problems.
- Implemented automatic telemetry correlation: all telemetry reported within the scope of the request is correlated to RequestTelemetry reported for the request.
- Implemented [Correlation HTTP protocol](https://github.com/lmolkova/correlation/blob/master/http_protocol_proposal_v1.md): default headers to pass Operation Root Id and Parent Id were changed. This version is backward compatible with previously supported headers. 
- Implemented injection into the HTTP stack for .NET 4.6 to leverage DiagnosticSource to gain access to the WebRequest and WebResponse objects for header injections, without the need of using the profiler.
- Dependency to System.Diagnostics.DiagnosticsSource package is added for Web SDK on .NET 4.5.
- Improvements to exception statistics, e.g. 2 of each type of exception will be output via TrackException
- New ```AspNetDiagnosticTelemetryModule``` introduced for Web SDK on .NET 4.5, it consumes events from [Microsoft.AspNet.TelemetryCorrelation package](https://github.com/aspnet/AspNetCorrelationIdTracker) about incoming Http requests.
- Dependency to Microsoft.AspNet.TelemetryCorrelation package is added for Web SDK on .NET 4.5.
- Report new performance counter \Process(??APP_WIN32_PROC??)\% Processor Time Normalized that represents process CPU normalized by the processors count

## Version 2.3.0
- Includes all changes since 2.2.0 stable release.
- Exception statistics feature introduced in beta version is removed.

## Version 2.3.0-beta3
- Exception statistics improvements and other minor bug fixes. [Full list.] (https://github.com/Microsoft/ApplicationInsights-dotnet-server/milestone/19?closed=1)
- Cross Components Correlation ID changed from SHA(instrumentation key) to Application ID retrieved from http endpoint `api/profiles/{ikey}/appId`.

## Version 2.3.0-beta2
- Automatic collection of first chance exceptions statistics. Use a query like this in Application Analytics to query for this statistics:
  ```
  customMetrics
  | where timestamp > ago(5d)
  | where name == "Exceptions thrown" 
  | extend type = tostring(customDimensions.type), method = tostring(customDimensions.method), operation = tostring(customDimensions.operation) 
  | summarize sum(value), sum(valueCount) by type, method, operation 
  ```
- Add dependency collection for System.Data.SqlClient.SqlConnection.Open and System.Data.SqlClient.SqlConnection.OpenAsync by Profiler instrumentation. Dependencies are sent only for failed connections.
- Top 5 CPU reporting for Live Metrics Stream (aka QuickPulse). QuickPulseTelemetryModule now reports the names and CPU consumption values of top 5 CPU consuming processes.

## Version 2.3.0-beta1
- Added the ability to correlate http request made between different components represented by different application insights resources. This feeds into the improved [application map experience](http://aka.ms/AiAppMapPreview).

## Version 2.2.0
- Includes all changes since 2.1.0 stable release.
- [Fixed issue with identifying which environment generated an event](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/248)

## Version 2.2.0-beta6
- [Fixed redundant dependency items issue](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/196)
- [Fixed issue reporting CPU Metric](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/225)
- [Fixed source of web app instance identification](https://github.com/Microsoft/ApplicationInsights-dotnet-server/issues/226)
- Updated package references.
- DependencyCollection nuget package was updated to Agent.Intercept nuget version 2.0.6.

## Version 2.2.0-beta4
- ```DomainNameRoleInstanceTelemetryInitializer``` is obsolete. Role instance is still populated with machine name as it was before.
- New ```AzureWebAppRoleEnvironmentTelemetryInitializer``` telemetry initializer that populates role name and role instance name for Azure Web Apps.
- Support of performance collection and live metrics for Azure Web Apps is enabled.

## Version 2.2.0-beta3
- New property `DefaultCounters` in `PerformanceCollectorModule` to control the list of standard counters that will be collected
- Default performance counters will be reported as metrics
- When you instantiate `DependencyTrackingTelemetryModule` in code it will not detect certain http dependencies as Azure Storage calls. You need to register a telemetry initializer `HttpDependenciesParsingTelemetryInitializer` to enable this functionality. This telemetry initializer will be registered automatically during NuGet installation.
- DependencyCollection nuget package was updated to Agent.Intercept nuget version 2.0.5.
- The list of userAgent substrings that indicate that traffic is from a synthetic source was minimized for performance reasons. If you want to include more substrings please add them under SyntheticUserAgentTelemetryInitializer/Filters. (List of filters that were used before is saved as a comment in the configuration file)
- Added HTTP dependencies parsing support for Azure tables, queues, and services (.svc & .asmx).
- Added automatic collection of source component correlation id (instrumenation key hash) for incoming requests and target component correlation id for dependencies.

## Version 2.2.0-beta2

- DependencyCollection nuget package was updated to Agent.Intercept nuget version 2.0.1. Agent.Intercept nuget was updated to EventSource.Redist version 1.1.28. 
- SQL dependencies will have SQL error message being added to custom properties collection if application uses profiler instrumentation (either instrumented with StatusMonitor or just have StatusMonitor on the box with the app)
- Allow all characters in custom counters ReportAs property.
- QuickPulse (Live Metrics Stream) was updated to include Live Failures

## Version 2.2.0-beta1

- ResultCode for successful Sql calls will be collected as 0 (before it was not sent).
- Fixed ResultCode sometimes not being collected for failed dependencies
- RequestTelemetry.UserAgent is collected automatically. 

## Version 2.1.0-beta4

- No code changes. Updated to Core 2.1-beta4.

## Version 2.1.0-beta3
- Remove support for HTTP dependencies in .NET 4.5.2 (4.5.2 applications running on 4.5.2; 4.5.2 applications running on 4.6 are still supported) without Status Monitor on the box.
- Add http verb to dependency name collected by SDK without Status Monitor on the box


## Version 2.1.0-beta2
- Http requests to LiveMetricsStream (Feature not surfaced in UI yet) backend were tracked as dependencies. They will be filtered out starting this version.
- There are no other changes 

## Version 2.1.0-beta1

- Upgraded to depend on EventSource.Redist nuget version 1.1.28
- Upgraded to depend on Microsoft.Bcl nuget version 1.1.10
- LiveMetricsStream feature is introduced (Not surfaced in UI yet)

## Version 2.0.0 
- Performance counter collection is no longer supported when running under IIS Express.

## Version 2.0.0-rc1

**Dependencies:**

- Http dependency success is determined on the base of http status code. Before it was true if there was no exception. But when one uses HttpClient there is no exceptions so all dependencies were marked as successful. Also in case if response is not available status code was set to -1. Now now status code will be reported.

## Version 2.0.0-beta4

**Web:**

- WebApps AlwaysOn requests with ResponseCode less than 400 will be filtered out. 
- User agent and request handler filters can be configured. Previous behavior filtered out only a default set of request handlers and user agent strings, 
  now custom filters can be added to the ApplicationInsights.config file through the ```TelemetryProcessors``` section. 
  Telemetry for requests with HttpContext.Current that matches these filters will not be sent.
- If multiple simultaneous calls are made on a ```SqlCommand``` object, only one dependency is recorded. The second
  call will be failed immediately by ```SqlCommand``` and will not be recorded as a dependency.

## Version 2.0.0-beta3
**Web:**

- Use ```OperationCorrelationTelemetryInitializer``` instead of ```OperationIdTelemetryInitializer```
- User Agent and Client IP will not be collected by default. User Agent telemetry initializer was removed
- ```DependencyTelemetry.Async``` field will not be collected by dependency collector telemetry module
- Static content and diagnostics requests will not be collected by request telemetry module. Use ```HandlersToFilter``` of ```RequestTrackingTelemetryModule``` collection to filter out requests generated by certain http handlers
- Autogenerated request telemetry is accessible though HttpContext extension method: System.Web.HttpContextExtension.GetRequestTelemetry

## Version 2.0.0-beta2
**Web:**

- RequestTelemetry.Name is not initialized any longer. RequestTelemetry.Context.Operaiton.Name will be used instead.
- Response code 401 is part of the normal authentication handshake and will result in a succesfull request.

**WindowsServer**

- DeviceTelemetryInitializer is not installed by default any more.

## Version 2.0.0-beta1

**Web:**

- Added `Microsoft.ApplicationInsights.Web.AccountIdTelemetryInitializer`, `Microsoft.ApplicationInsights.Web.AuthenticatedUserIdTelemetryInitializer` that initialize authenticated user context as set by Javascript SDK.
- Added `Microsoft.ApplicationInsights.WindowsServer.TelemetryChannel.ITelemetryProcessor` and fixed-rate Sampling support as an implementation of it.
- Added `Microsoft.ApplicationInsights.WindowsServer.TelemetryChannel.TelemetryChannelBuilder` that allows creation of a `Microsoft.ApplicationInsights.WindowsServer.TelemetryChannel.ServerTelemetryChannel` with a set of `Microsoft.ApplicationInsights.WindowsServer.TelemetryChannel.ITelemetryProcessor`.

## Version 1.2.0
**Web:**

- Telemetry initializers that do not have dependencies on ASP.NET libraries were moved to the new dependency nuget "Microsoft.ApplicationInsights.WindowsServer"
- Microsoft.ApplicationInsights.Web.dll was renamed on Microsoft.AI.Web.dll
- Microsoft.Web.TelemetryChannel nuget was renamed on Microsoft.WindowsServer.TelemetryChannel. TelemetryChannel assembly was also renamed.
- All namespaces that are part of Web SDK were changed to exlude "Extensibility" part. That incudes all telemetry initializers in applicationinsights.config and ApplicationInsightsWebTracking module in web.config.

**Dependencies:**

- Dependencies collected using runtime instrumentaiton agent (enabled via Status Monitor or Azure WebSite extension) will not be marked as asynchronous if there are no HttpContext.Current on the thread.
- Property ```SamplingRatio``` of ```DependencyTrackingTelemetryModule``` does nothing and marked as obsolete.

**Performance Counters**

- Microsoft.ApplicationInsights.Extensibility.PerfCounterCollector assembly was renamed on Microsoft.AI.PerfCounterCollector

**WindowsServer**

- First version of the package. The package has common logic that will be shared between Web and Non-Web Windows applications.

## Version 1.0.0

**Web:**

- Moved telemetry initializers and telemetry modules from separate sub-namespaces to the root 
  `Microsoft.ApplicationInsights.Extensibility.Web` namespace.
- Removed "Web" prefix from names of telemetry initializers and telemetry modules because it is already included in the 
  `Microsoft.ApplicationInsights.Extensibility.Web` namespace name.
- Moved `DeviceContextInitializer` from the `Microsoft.ApplicationInsights` assembly to the 
  `Microsoft.ApplicationInsights.Extensibility.Web` assembly and converted it to an `ITelemetryInitializer`.

**Dependencies:**

- Change namespace and assembly names from `Microsoft.ApplicationInsights.Extensibility.RuntimeTelemetry` to 
  `Microsoft.ApplicationInsights.Extensibility.DependencyCollector` for consistency with the name of the NuGet package.
- Rename `RemoteDependencyModule` to `DependencyTrackingTelemetryModule`.

**Performance Counters**

- Rename 'CustomPerformanceCounterCollectionRequest' to 'PerformanceCounterCollectionRequest'.

## Version 0.17

**Web:**

- Removed dependency to EventSource NuGet for the framework 4.5 applications.
- Anonymous User and Session cookies will not be generated on server side. Telemetry modules ```WebSessionTrackingTelemetryModule``` and ```WebUserTrackingTelemetryModule``` are no longer supported and were removed from ApplicationInsights.config file. Cookies from JavaScript SDK will be respected.
- Persistence channel optimized for high-load scenarios is used for web SDK. "Spiral of death" issue fixed. Spiral of death is a condition when spike in telemetry items count that greatly exceeds throttling limit on endpoint will lead to retry after certain time and will be throttled during retry again.
- Developer Mode is optimized for production. If left by mistake it will not cause as big overhead as before attempting to output additional information.
- Developer Mode by default will only be enabled when application is under debugger. You can override it using ```DeveloperMode``` property of  ```ITelemetryChannel``` interface.

**Dependencies:**

- Removed dependency to EventSource NuGet for the framework 4.5 applications.

**Performance Counters**

- Diagnostic messages pertaining to performance counter collection are now merged into a single unified message that is logged at application start-up. Detailed failure information is still available through PerfView.

## Version 0.15

**Web:**

- Application Insights Web package now detects the traffic from Availability monitoring of Application Insights and marks it with specific ```SyntheticSource``` property.

## Version 0.13

No release notes for older versions available.
