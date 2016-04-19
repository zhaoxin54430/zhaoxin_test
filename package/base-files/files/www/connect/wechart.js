var Wechat_loadIframe = null;
var Wechat_noResponse = null;
var Wechat_callUpTimestamp = 0;
function Wechat_putNoResponse(ev){
    clearTimeout(Wechat_noResponse);
}
function Wechat_errorJump()
{
    var now = new Date().getTime();
    if((now - Wechat_callUpTimestamp) > 4*1000){
        return;
    }
    alert('该浏览器不支持自动跳转微信请手动打开微信\n如果已跳转请忽略此提示');
}
Wechat_myHandler = function(error) {
    Wechat_errorJump();
};
function Wechat_createIframe(){
    var iframe = document.createElement("iframe");
    iframe.style.cssText = "display:none;width:0px;height:0px;";
    document.body.appendChild(iframe);
    Wechat_loadIframe = iframe;
}
function jsonpCallback(result){
    if(result && result.success){
        //alert('WeChat will call up : ' + result.success + '  data:' + result.data);
        var ua=navigator.userAgent;
        if (ua.indexOf("iPhone") != -1 ||ua.indexOf("iPod")!=-1||ua.indexOf("iPad") != -1) {   //iPhone
            document.location = result.data;
        }else{
            Wechat_createIframe();
            Wechat_callUpTimestamp = new Date().getTime();
            Wechat_loadIframe.src=result.data;
            Wechat_noResponse = setTimeout(function(){
                Wechat_errorJump();
            },3000);
        }
    }else if(result && !result.success){
        alert(result.data);
    }
}
function Wechat_GotoRedirect(appId, extend, timestamp, sign, shopId, authUrl, mac, ssid, bssid){
    var url = "https://wifi.weixin.qq.com/operator/callWechatBrowser.xhtml?appId=" + appId
        + "&extend=" + extend
        + "&timestamp=" + timestamp
        + "&sign=" + sign;
    if(authUrl && shopId){
        url = "https://wifi.weixin.qq.com/operator/callWechat.xhtml?appId=" + appId
            + "&extend=" + extend
            + "&timestamp=" + timestamp
            + "&sign=" + sign
            + "&shopId=" + shopId
            + "&authUrl=" + encodeURIComponent(authUrl)
            + "&mac=" + mac
            + "&ssid=" + ssid
    }
    var script = document.createElement('script');
    script.setAttribute('src', url);
    document.getElementsByTagName('head')[0].appendChild(script);
}
var Wechat_xmlhttp;
var Wechat_tryTimes=0;
function Wechat_requestTempConnect()
{
    Wechat_xmlhttp=null;
    if (window.XMLHttpRequest)
    {// code for all new browsers
        Wechat_xmlhttp=new XMLHttpRequest();
    }
    else if (window.ActiveXObject)
    {// code for IE5 and IE6
        Wechat_xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
    }
    if (Wechat_xmlhttp!=null)
    {
        var url = 'request_connect_allow';
        Wechat_xmlhttp.onreadystatechange=Wechat_state_Change;
        Wechat_xmlhttp.open("GET",url,true);
        Wechat_xmlhttp.send(null);
    }
    else
    {
        alert("你的浏览器不支持XMLHTTP.");
    }
}
function Wechat_state_Change()
{
    if (Wechat_xmlhttp.readyState==4)
    {
        if (Wechat_xmlhttp.status==200)
        {
            Wechat_callWechatBrowser();
        }
        else if (Wechat_xmlhttp.status==404)
        {// 404 not find client from share memory
            alert("认证失败，请重新连接wifi再尝试！");
        }
        else
        {
            if(Wechat_tryTimes < 3)
            {
                Wechat_requestTempConnect();
            }
            else
            {
                alert("认证失败，请重新连接wifi再尝试！");
            }
            Wechat_tryTimes++;
        }
    }
}
function Wechat_getParameter(param)
{
    var query = window.location.search;
    var iLen = param.length;
    var iStart = query.indexOf(param);
    if (iStart == -1)
        return "";
    iStart += iLen + 1;
    var iEnd = query.indexOf("&", iStart);
    if (iEnd == -1)
        return query.substring(iStart);
    return query.substring(iStart, iEnd);
}
function Wechat_callWechatBrowser(){
    var appId = Wechat_getParameter("appId");
    var extend = Wechat_getParameter("extend");
    var shopId = Wechat_getParameter("shopId");
    var mac = Wechat_getParameter("mac");
    var authUrl = decodeURIComponent(Wechat_getParameter("authUrl"));
    var secretKey = Wechat_getParameter("secretKey");
    var bssid = "";
    var ssid = "";
    var timestamp = Date.parse(new Date());

    var toSign = appId + extend + timestamp + shopId + authUrl + mac + ssid + secretKey;
    var sign= hex_md5(toSign);
    Wechat_GotoRedirect(appId, extend, timestamp, sign, shopId, authUrl, mac, ssid, bssid);
}
/*<script type="text/javascript">
    document.addEventListener('visibilitychange', Wechat_putNoResponse, false);
</script>*/


