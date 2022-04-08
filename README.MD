<h1>Use basic authentication via nginx proxy to access aws</h1>
<h3>
docker image base on OpenResty 

use library <a href="https://github.com/Egor-Skriptunoff/pure_lua_SHA.git">sha2.lua</a>
</h3>
Use <b>basic authentication</b> convert to <b>aws signature 4</b>:
```
//example: </servicename.us-east-1.es.amazonaws.com>THISAWSID
username format: </awsHost>awsId

//example: ThisAwsSecret
password format: awsSecret
```