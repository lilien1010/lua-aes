
some phper maybe find that the libraries in nginx-lua is not enough,
like aes mcrypt with ECB mode,
so  I create this.

like encrypt with PHP:
```php
mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,$text, MCRYPT_MODE_ECB );
```

encrypt with lua:
```lua
local data      =   'wait to be encrypted'
local key       =   '01234567890123456' --length is 16
local mc_ecb    = require("resty.ecb_mcrypt")
local ecb       = mc_ecb:new();
local enc_data  = ecb:encrypt(key,data );
ngx.print(enc_data)
--  you must use 'ngx.print' rather then 'ngx.say'
-- while 'ngx.say' will append a '\n'  at the end of string
```

mean while,you will need to install libmcrypt,
because the lua-aes will load  the libmcrypt with FFI,
try to install libmcrypt
```
yum install libmcrypt libmcrypt-devel
```
