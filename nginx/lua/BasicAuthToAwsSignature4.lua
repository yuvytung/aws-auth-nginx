local sha = require("sha2");
local nl = string.char(10);
local awsAlgorithm = "AWS4-HMAC-SHA256" ;
local signedHeaders = "host;x-amz-content-sha256;x-amz-date";

local awsTime =  os.date("%Y%m%dT%H%M%SZ",os.time());
local awsDate =  awsTime:sub(0,8);

local httpRequestMethod = ngx.var.request_method;
local rootUri = ngx.var.request_uri;
local canonicalURI = rootUri;
local canonicalQueryString = "";
local requestPayloadHashHex = sha.sha256("");

function hmacHex(key,value)
    return sha.hmac(sha.sha256,sha.hex_to_bin(key),value);
end
function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end)):lower()
end

if nil ~= rootUri:find("?") then
    canonicalURI = root_uri:sub(0,root_uri:find("?")-1)
    canonicalQueryString = root_uri:sub(rootUri:find("?")+1)
end
if   nil ~=ngx.req.get_body_data() then
    requestPayloadHashHex = sha.sha256(ngx.req.get_body_data())
end
local basicAuthDecoded =  ngx.decode_base64(string.sub(ngx.var.http_authorization,string.len("Basic ")+1));
local awsId =  basicAuthDecoded:match(".+:"):gsub(":","");
local awsSecret =   basicAuthDecoded:match(":.+"):gsub(":","")
local awsHost = awsId:match("[^</][%w-.]*[^>]");
local awsHostName = awsHost:match("[%w-]*");
local awsRegion = awsHost:match("[%w-]*",awsHostName:len()+2);
local awsService = awsHost:match("[%w-]*",1+
        awsHostName:len()+1+
        awsRegion:len()+1);
local credentialScope = awsDate.."/"..awsRegion.."/"..awsService.."/aws4_request";
awsId = awsId:gsub("</[%w-._]*>","");
local canonicalHeaders = "host:"..awsHost..nl..
        "x-amz-content-sha256:"..requestPayloadHashHex..nl..
        "x-amz-date:"..awsTime..nl;
local canonicalRequest = httpRequestMethod..nl..
        canonicalURI..nl..
        canonicalQueryString..nl..
        canonicalHeaders..nl..
        signedHeaders..nl..
        requestPayloadHashHex;
local stringToSign = "AWS4-HMAC-SHA256"..nl..
        awsTime..nl..
        credentialScope..nl..
        sha.sha256(canonicalRequest);
local signingKey = hmacHex(hmacHex(hmacHex(hmacHex(("AWS4"..awsSecret):tohex(),awsDate),awsRegion),awsService),"aws4_request");
local signing = hmacHex(signingKey,stringToSign);
-- Set Proxy Headers
ngx.req.set_header("Authorization",awsAlgorithm..
        " Credential="..awsId.."/"..credentialScope..
        ", SignedHeaders="..signedHeaders..
        ", Signature="..signing);
ngx.req.set_header("X-Amz-Date", awsTime);
ngx.req.set_header("Host",awsHost);
ngx.req.set_header("X-Amz-Content-Sha256",requestPayloadHashHex);
