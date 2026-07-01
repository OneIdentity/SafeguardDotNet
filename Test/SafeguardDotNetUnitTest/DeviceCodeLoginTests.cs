// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetUnitTest;

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

public class DeviceCodeLoginTests
{
    private const string Appliance = "appliance.test";

    private const string DeviceLoginUrl = "https://appliance.test/RSTS/oauth2/DeviceLogin";

    private const string TokenUrl = "https://appliance.test/RSTS/oauth2/token";

    private static readonly DateTime ClockStart = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // ---- 1. Argument validation and callback ownership ----

    [Fact]
    public async Task EmptyAppliance_ThrowsArgumentException()
    {
        var transport = new FakeHttpTransport();
        var clock = new FakeClock(ClockStart);

        await Assert.ThrowsAsync<ArgumentException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                string.Empty,
                MakeParameters(info => { }),
                transport,
                clock,
                CancellationToken.None));
    }

    [Fact]
    public async Task NullParameters_ThrowsArgumentException()
    {
        var transport = new FakeHttpTransport();
        var clock = new FakeClock(ClockStart);

        await Assert.ThrowsAsync<ArgumentException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                null,
                transport,
                clock,
                CancellationToken.None));
    }

    [Fact]
    public async Task NullDisplayCallback_ThrowsArgumentException()
    {
        var transport = new FakeHttpTransport();
        var clock = new FakeClock(ClockStart);

        await Assert.ThrowsAsync<ArgumentException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                new DeviceCodeLoginParameters { DisplayCallback = null },
                transport,
                clock,
                CancellationToken.None));
    }

    [Fact]
    public async Task SuccessfulDeviceLogin_InvokesDisplayCallbackExactlyOnceWithParsedInfo()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess(
            deviceCode: "dev-abc",
            userCode: "WXYZ-1234",
            verificationUri: "https://appliance.test/RSTS/Device",
            verificationUriComplete: "https://appliance.test/RSTS/Device?user_code=WXYZ-1234",
            expiresIn: 280));
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        var callbackCount = 0;
        DeviceCodeInfo? captured = null;

        var clock = new FakeClock(ClockStart);
        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info =>
            {
                callbackCount++;
                captured = info;
            }),
            transport,
            clock,
            CancellationToken.None);

        Assert.Equal(1, callbackCount);
        Assert.NotNull(captured);
        Assert.Equal("https://appliance.test/RSTS/Device", captured!.VerificationUri);
        Assert.Equal("https://appliance.test/RSTS/Device?user_code=WXYZ-1234", captured.VerificationUriComplete);
        Assert.Equal("WXYZ-1234", captured.UserCode);
        Assert.Equal(280, captured.ExpiresIn);
    }

    // ---- 2. Device authorization request shape ----

    [Fact]
    public async Task DefaultScope_IsLocalProviderWhenScopeNull()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }),
            transport,
            new FakeClock(ClockStart),
            CancellationToken.None);

        var deviceBody = ParseBody(transport.Requests[0].Body);
        Assert.Equal("rsts:sts:primaryproviderid:local", deviceBody.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task DefaultClientId_IsEmptyString()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }),
            transport,
            new FakeClock(ClockStart),
            CancellationToken.None);

        var deviceBody = ParseBody(transport.Requests[0].Body);
        Assert.Equal(string.Empty, deviceBody.GetProperty("client_id").GetString());
    }

    [Fact]
    public async Task CustomScopeAndClientId_AreSerialized()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(
                info => { },
                clientId: "my-client",
                scope: "rsts:sts:primaryproviderid:corp"),
            transport,
            new FakeClock(ClockStart),
            CancellationToken.None);

        var deviceBody = ParseBody(transport.Requests[0].Body);
        Assert.Equal("my-client", deviceBody.GetProperty("client_id").GetString());
        Assert.Equal("rsts:sts:primaryproviderid:corp", deviceBody.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task DeviceLoginUrl_HasNoTrailingSlash()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }),
            transport,
            new FakeClock(ClockStart),
            CancellationToken.None);

        Assert.Equal(DeviceLoginUrl, transport.Requests[0].Url);
    }

    // ---- 3. Disabled-grant detection ----

    [Theory]
    [InlineData("device code grant type is not allowed")]
    [InlineData("Device Code grant type is not allowed")]
    [InlineData("DEVICE CODE GRANT TYPE IS NOT ALLOWED")]
    public async Task DisabledGrant_HtmlBody_ThrowsClearEnableMessage(string phrase)
    {
        var htmlBody = $"<html><body><h1>{phrase}</h1></body></html>";
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(Json(HttpStatusCode.BadRequest, htmlBody));

        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                CancellationToken.None));

        Assert.Contains("DeviceCode", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Allowed OAuth2 Grant Types", ex.Message, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.BadRequest, ex.HttpStatusCode);
        Assert.Equal(htmlBody, ex.Response);

        // Reactive detection only: no token polling occurs and no JSON parse leaks.
        Assert.Single(transport.Requests);
        Assert.Equal(DeviceLoginUrl, transport.Requests[0].Url);
    }

    [Fact]
    public async Task NonSuccessWithoutDisabledMarker_ThrowsGenericDeviceAuthError()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(Json(HttpStatusCode.InternalServerError, "boom"));

        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                CancellationToken.None));

        Assert.Contains("Device authorization request failed", ex.Message, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.InternalServerError, ex.HttpStatusCode);
        Assert.Equal("boom", ex.Response);
    }

    // ---- 4. Poll-loop transitions ----

    [Fact]
    public async Task AuthorizationPending_ContinuesPollingWithoutChangingInterval()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenError("authorization_pending"));
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        var clock = new FakeClock(ClockStart);
        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }, pollingIntervalSeconds: 5),
            transport,
            clock,
            CancellationToken.None);

        Assert.Equal(new[] { TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5) }, clock.Delays);
    }

    [Fact]
    public async Task SlowDown_IncreasesIntervalByFiveSeconds()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenError("slow_down"));
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        var clock = new FakeClock(ClockStart);
        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }, pollingIntervalSeconds: 5),
            transport,
            clock,
            CancellationToken.None);

        Assert.Equal(new[] { TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10) }, clock.Delays);
    }

    [Fact]
    public async Task PendingThenSlowDownThenSuccess_RecordsExpectedDelaysAndReturnsToken()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenError("authorization_pending"));
        transport.EnqueueTokenResponse(TokenError("slow_down"));
        transport.EnqueueTokenResponse(TokenSuccess("the-rsts-token"));

        var clock = new FakeClock(ClockStart);
        var token = await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }, pollingIntervalSeconds: 5),
            transport,
            clock,
            CancellationToken.None);

        using (token)
        {
            Assert.Equal("the-rsts-token", token.ToInsecureString());
        }

        Assert.Equal(
            new[] { TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10) },
            clock.Delays);
    }

    [Fact]
    public async Task TokenPoll_PostsDeviceCodeGrantWithDeviceCodeAndClientId()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess(deviceCode: "dev-xyz"));
        transport.EnqueueTokenResponse(TokenSuccess("rsts-token"));

        await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }),
            transport,
            new FakeClock(ClockStart),
            CancellationToken.None);

        var tokenRequest = transport.Requests[1];
        Assert.Equal(TokenUrl, tokenRequest.Url);

        var tokenBody = ParseBody(tokenRequest.Body);
        Assert.Equal(
            "urn:ietf:params:oauth:grant-type:device_code",
            tokenBody.GetProperty("grant_type").GetString());
        Assert.Equal("dev-xyz", tokenBody.GetProperty("device_code").GetString());
        Assert.Equal(string.Empty, tokenBody.GetProperty("client_id").GetString());
    }

    // ---- 5. Terminal poll failures ----

    [Fact]
    public async Task AccessDenied_ThrowsUserDeniedAndPreservesStatusAndBody()
    {
        var body = "{\"error\":\"access_denied\"}";
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(Json(HttpStatusCode.BadRequest, body));

        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                CancellationToken.None));

        Assert.Contains("denied", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.BadRequest, ex.HttpStatusCode);
        Assert.Equal(body, ex.Response);
    }

    [Fact]
    public async Task ExpiredToken_ThrowsExpiredAndPreservesStatusAndBody()
    {
        var body = "{\"error\":\"expired_token\"}";
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(Json(HttpStatusCode.BadRequest, body));

        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                CancellationToken.None));

        Assert.Contains("expired", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.BadRequest, ex.HttpStatusCode);
        Assert.Equal(body, ex.Response);
    }

    [Fact]
    public async Task UnknownError_ThrowsUnexpectedPollingErrorWithStatusAndBody()
    {
        var body = "{\"error\":\"invalid_grant\"}";
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(Json(HttpStatusCode.BadRequest, body));

        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                CancellationToken.None));

        Assert.Contains("Unexpected error during device code polling", ex.Message, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.BadRequest, ex.HttpStatusCode);
        Assert.Equal(body, ex.Response);
    }

    [Fact]
    public async Task NonJsonTokenFailure_ThrowsClearError_NotJsonException()
    {
        var htmlBody = "<html><body>500 Internal Server Error</body></html>";
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(Json(HttpStatusCode.InternalServerError, htmlBody));

        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                CancellationToken.None));

        Assert.Contains("non-JSON response", ex.Message, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.InternalServerError, ex.HttpStatusCode);
        Assert.Equal(htmlBody, ex.Response);
    }

    [Fact]
    public async Task DeadlineExceeded_ThrowsExpiredBeforeAuthenticated_WithoutWallClockWait()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess(expiresIn: 30));
        for (var i = 0; i < 10; i++)
        {
            transport.EnqueueTokenResponse(TokenError("authorization_pending"));
        }

        var clock = new FakeClock(ClockStart);
        var ex = await Assert.ThrowsAsync<SafeguardDotNetException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }, pollingIntervalSeconds: 5),
                transport,
                clock,
                CancellationToken.None));

        Assert.Equal("Device code expired before user authenticated.", ex.Message);

        // expires_in 30 with a 5s interval allows exactly six polls before the deadline.
        Assert.Equal(6, clock.Delays.Count);
    }

    // ---- 6. Cancellation ----

    [Fact]
    public async Task CancellationBeforeDeviceLogin_AbortsWithNoHttpCalls()
    {
        var transport = new FakeHttpTransport();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                new FakeClock(ClockStart),
                cts.Token));

        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task CancellationWhileWaiting_ThrowsAndMakesNoFurtherHttpCalls()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());

        var clock = new FakeClock(ClockStart) { ThrowOnDelay = true };

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                clock,
                CancellationToken.None));

        // Only the device-login call happened; the token endpoint was never polled.
        Assert.Single(transport.Requests);
        Assert.Equal(DeviceLoginUrl, transport.Requests[0].Url);
    }

    [Fact]
    public async Task CancellationAfterPendingPoll_AbortsBeforeNextRequest()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenError("authorization_pending"));

        using var cts = new CancellationTokenSource();
        transport.OnTokenRequestServed = () => cts.Cancel();

        var clock = new FakeClock(ClockStart);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => DeviceCodeLogin.RequestRstsDeviceTokenAsync(
                Appliance,
                MakeParameters(info => { }),
                transport,
                clock,
                cts.Token));

        // Device login plus exactly one pending poll; no third request after cancellation.
        Assert.Equal(2, transport.Requests.Count);
        Assert.Single(clock.Delays);
    }

    // ---- 7. Connect/exchange boundary ----

    [Fact]
    public async Task RequestRstsDeviceToken_ReturnsPolledRstsToken()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenSuccess("rsts-secret"));

        var token = await DeviceCodeLogin.RequestRstsDeviceTokenAsync(
            Appliance,
            MakeParameters(info => { }),
            transport,
            new FakeClock(ClockStart),
            CancellationToken.None);

        using (token)
        {
            Assert.Equal("rsts-secret", token.ToInsecureString());
        }
    }

    [Fact]
    public async Task ConnectInternal_PassesPolledTokenToExchangerExactlyOnce()
    {
        var transport = new FakeHttpTransport();
        transport.EnqueueDeviceResponse(DeviceSuccess());
        transport.EnqueueTokenResponse(TokenSuccess("rsts-exchange-me"));

        var exchanger = new FakeExchanger();

        await DeviceCodeLogin.ConnectInternalAsync(
            Appliance,
            MakeParameters(info => { }),
            apiVersion: Safeguard.DefaultApiVersion,
            ignoreSsl: true,
            transport,
            new FakeClock(ClockStart),
            exchanger.ExchangeAsync,
            CancellationToken.None);

        Assert.Equal(1, exchanger.CallCount);
        Assert.Equal("rsts-exchange-me", exchanger.CapturedToken);
    }

    [Fact]
    public async Task ConnectInternal_NullExchanger_ThrowsArgumentNullException()
    {
        var transport = new FakeHttpTransport();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => DeviceCodeLogin.ConnectInternalAsync(
                Appliance,
                MakeParameters(info => { }),
                apiVersion: Safeguard.DefaultApiVersion,
                ignoreSsl: false,
                transport,
                new FakeClock(ClockStart),
                null!,
                CancellationToken.None));
    }

    // ---- Helpers ----

    private static DeviceCodeLoginParameters MakeParameters(
        Action<DeviceCodeInfo> displayCallback,
        int pollingIntervalSeconds = 5,
        string? clientId = null,
        string? scope = null)
    {
        var parameters = new DeviceCodeLoginParameters
        {
            DisplayCallback = displayCallback,
            PollingIntervalSeconds = pollingIntervalSeconds,
            Scope = scope,
        };

        if (clientId != null)
        {
            parameters.ClientId = clientId;
        }

        return parameters;
    }

    private static HttpResponseMessage DeviceSuccess(
        string deviceCode = "device-code",
        string userCode = "ABCD-1234",
        string verificationUri = "https://appliance.test/RSTS/Device",
        string verificationUriComplete = "https://appliance.test/RSTS/Device?user_code=ABCD-1234",
        int expiresIn = 300)
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["device_code"] = deviceCode,
            ["user_code"] = userCode,
            ["verification_uri"] = verificationUri,
            ["verification_uri_complete"] = verificationUriComplete,
            ["expires_in"] = expiresIn,
        });

        return Json(HttpStatusCode.OK, json);
    }

    private static HttpResponseMessage TokenSuccess(string accessToken)
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["access_token"] = accessToken,
        });

        return Json(HttpStatusCode.OK, json);
    }

    private static HttpResponseMessage TokenError(string error)
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["error"] = error,
        });

        return Json(HttpStatusCode.BadRequest, json);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
    }

    private static JsonElement ParseBody(string body)
    {
        using var document = JsonDocument.Parse(body);
        return document.RootElement.Clone();
    }

    private sealed class RecordedRequest
    {
        public RecordedRequest(string url, string body)
        {
            Url = url;
            Body = body;
        }

        public string Url { get; }

        public string Body { get; }
    }

    private sealed class FakeHttpTransport : HttpClient
    {
        private readonly StubHandler _handler;

        public FakeHttpTransport()
            : this(new StubHandler())
        {
        }

        private FakeHttpTransport(StubHandler handler)
            : base(handler)
        {
            _handler = handler;
        }

        public List<RecordedRequest> Requests => _handler.Requests;

        public Action? OnTokenRequestServed
        {
            get => _handler.OnTokenRequestServed;
            set => _handler.OnTokenRequestServed = value;
        }

        public void EnqueueDeviceResponse(HttpResponseMessage result) => _handler.EnqueueDeviceResponse(result);

        public void EnqueueTokenResponse(HttpResponseMessage result) => _handler.EnqueueTokenResponse(result);

        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly Queue<HttpResponseMessage> _deviceResponses = new();
            private readonly Queue<HttpResponseMessage> _tokenResponses = new();

            public List<RecordedRequest> Requests { get; } = new();

            public Action? OnTokenRequestServed { get; set; }

            public void EnqueueDeviceResponse(HttpResponseMessage result) => _deviceResponses.Enqueue(result);

            public void EnqueueTokenResponse(HttpResponseMessage result) => _tokenResponses.Enqueue(result);

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                var url = request.RequestUri!.ToString();
                var body = request.Content == null
                    ? string.Empty
                    : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

                Requests.Add(new RecordedRequest(url, body));

                if (url.EndsWith("/DeviceLogin", StringComparison.Ordinal))
                {
                    return _deviceResponses.Dequeue();
                }

                var response = _tokenResponses.Dequeue();
                OnTokenRequestServed?.Invoke();
                return response;
            }
        }
    }

    private sealed class FakeClock : IDeviceCodeClock
    {
        private DateTime _utcNow;

        public FakeClock(DateTime start)
        {
            _utcNow = start;
        }

        public List<TimeSpan> Delays { get; } = new();

        public bool ThrowOnDelay { get; set; }

        public DateTime UtcNow => _utcNow;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            Delays.Add(delay);
            _utcNow = _utcNow.Add(delay);

            if (ThrowOnDelay)
            {
                throw new OperationCanceledException();
            }

            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private sealed class FakeExchanger
    {
        public int CallCount { get; private set; }

        public string? CapturedToken { get; private set; }

        public Task<ISafeguardConnection> ExchangeAsync(
            string appliance,
            SecureString rstsAccessToken,
            int apiVersion,
            bool ignoreSsl,
            CancellationToken cancellationToken)
        {
            CallCount++;
            CapturedToken = rstsAccessToken.ToInsecureString();
            return Task.FromResult<ISafeguardConnection>(null!);
        }
    }
}
