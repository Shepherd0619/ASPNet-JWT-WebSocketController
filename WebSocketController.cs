// WebSocketController
// Shepherd Zhu
using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using SimpleJSON;

public class WebSocketController : ControllerBase
{
    private readonly ILogger _logger;
    
    /// <summary>
    /// UserId，WebSocket相对应的WebSocket连接列表
    /// </summary>
    public static Dictionary<string, WebSocket> UserConnections =
        new Dictionary<string, WebSocket>();

    // 按照协议头分类回调
    private readonly Dictionary<string, Action<string, string>> _protocolCallbacks =
        new Dictionary<string, Action<string, string>>();

    /// <summary>
    /// 注册回调
    /// </summary>
    /// <param name="protocol">协议头</param>
    /// <param name="callback"></param>
    public void RegisterProtocolCallback(string protocol, Action<string, string> callback)
    {
        if (!_protocolCallbacks.TryAdd(protocol, callback))
        {
            _protocolCallbacks[protocol] += callback;
        }

        _logger.LogInformation(
            $"[{DateTime.Now}][{GetType()}.RegisterProtocolCallback] protocol is {protocol}"
        );
    }

    /// <summary>
    /// 调用回调
    /// </summary>
    /// <param name="protocol">协议头</param>
    /// <param name="id"></param>
    /// <param name="data">数据</param>
    public void InvokeProtocolCallback(string protocol, string id, string data)
    {
        if (_protocolCallbacks.TryGetValue(protocol, out var callback))
        {
            _logger.LogInformation(
                $"[{DateTime.Now}][{GetType()}.InvokeProtocolCallback] Invoke! protocol is {protocol}"
            );
            try
            {
                callback?.Invoke(id, data);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    $"[{DateTime.Now}][{GetType()}.InvokeProtocolCallback] ERROR! {ex}"
                );
            }
        }
        else
        {
            _logger.LogWarning(
                $"[{DateTime.Now}][{GetType()}.InvokeProtocolCallback] No protocol called {protocol} exist!"
            );
        }
    }

    public WebSocketController(ILogger<WebSocketController> logger)
    {
        _logger = logger;

        // Register protocol callback here.
    }

    #region Echo
    [Route("/ws")]
    public async Task Get()
    {
        if (HttpContext.WebSockets.IsWebSocketRequest)
        {
            using var webSocket = await HttpContext.WebSockets.AcceptWebSocketAsync();
            // 验证JWT
            var header = HttpContext.Request.Headers;

            if (!header.TryGetValue("Authorization", out var subProtocol))
            {
                _logger.LogWarning(
                    $"[{DateTime.Now}][{GetType()}.Get] Unable to get Authorization from header. Abort."
                );
                await webSocket.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "Unauthorized",
                    CancellationToken.None
                );
                return;
            }

            var token = subProtocol.ToString().Trim();

            var userId = await JwtTokenHelper.GetUserIdFromToken(token);

            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning(
                    $"[{DateTime.Now}][{GetType()}.Get] Unable to get userId from JwtToken. Abort."
                );
                await webSocket.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "Unauthorized",
                    CancellationToken.None
                );
                return;
            }

            if (UserConnections.TryGetValue(userId, out var value))
            {
                _logger.LogWarning(
                    $"[{DateTime.Now}][{GetType()}.Get] Looks like user {userId} already connected to the server. Will kick the old connection."
                );
                await UserConnections[userId]
                    .CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Kicked due to login in other place.",
                        CancellationToken.None
                    );
                UserConnections[userId] = webSocket;
            }
            else
            {
                UserConnections.Add(userId, webSocket);
                _logger.LogInformation(
                    $"[{DateTime.Now}][{GetType()}.Get] User {userId} connected!"
                );
            }

            // 开始收发消息
            await Echo(webSocket, userId);
        }
        else
        {
            HttpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        }
    }

    private async Task Echo(WebSocket webSocket, string userId)
    {
        var buffer = new byte[1024 * 4];
        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromSeconds(25)); // 设置超时时间为25秒
        WebSocketReceiveResult receiveResult;
        try
        {
            receiveResult = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), cts.Token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                $"[{DateTime.Now}][{GetType()}.Echo] Timeout reached. Now abort {userId}'s connection."
            );
            webSocket.Abort();
            UserConnections.Remove(userId);
            return;
        }

        while (!receiveResult.CloseStatus.HasValue)
        {
            var msgString = ReturnCleanASCII(System.Text.Encoding.UTF8.GetString(buffer));

            switch (msgString)
            {
                // 心跳包
                case "ping":
                    await webSocket.SendAsync(
                        new ArraySegment<byte>(
                            Encoding.UTF8.GetBytes("pong"),
                            0,
                            receiveResult.Count
                        ),
                        receiveResult.MessageType,
                        receiveResult.EndOfMessage,
                        CancellationToken.None
                    );
                    break;

                default:
                    // TODO: 解析成json并根据action字段判断执行对应函数
                    try
                    {
                        OnReceiveJson(userId, msgString);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(
                            $"[{DateTime.Now}][{GetType()}.Echo] SimpleJSON error on {userId}'s request! Possibly not a JSON."
                                + $"\nContent of msgString:\n{msgString}"
                        );
                    }
                    break;
            }

            buffer = new byte[1024 * 4];

            try
            {
                receiveResult = await webSocket.ReceiveAsync(
                    new ArraySegment<byte>(buffer),
                    cts.Token
                );
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    $"[{DateTime.Now}][{GetType()}.Echo] Timeout reached. Now abort {userId}'s connection."
                );
                webSocket.Abort();
                UserConnections.Remove(userId);
                return;
            }
        }

        UserConnections.Remove(userId);

        await webSocket.CloseAsync(
            receiveResult.CloseStatus.Value,
            receiveResult.CloseStatusDescription,
            CancellationToken.None
        );
    }

    public string ReturnCleanASCII(string s)
    {
        StringBuilder sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            //if ((int)c > 127) // you probably don't want 127 either
            //    continue;
            if ((int)c < 32) // I bet you don't want control characters
                continue;
            if (c == '%')
                continue;
            if (c == '?')
                continue;
            sb.Append(c);
        }

        return sb.ToString();
    }
    #endregion

    private void OnReceiveJson(string id, string msgString)
    {
        JSONNode response = JSONNode.Parse(msgString);
        var action = response["action"].ToString().Trim('"');

        InvokeProtocolCallback(action, id, msgString);
    }

    public async void Disconnect(string id)
    {
        if (!UserConnections.TryGetValue(id, out var webSocket))
        {
            return;
        }

        await webSocket.CloseAsync(
            WebSocketCloseStatus.NormalClosure,
            string.Empty,
            CancellationToken.None
        );
        UserConnections.Remove(id);
    }
}
