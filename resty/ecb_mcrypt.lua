--[[
	12:24 2015/9/30	  lilien

]]
local ffi = require 'ffi'
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local setmetatable = setmetatable
local _M = { }
local mt = { __index = _M }

 ffi.cdef[[
struct CRYPT_STREAM;
typedef struct CRYPT_STREAM *MCRYPT;

MCRYPT mcrypt_module_open(char *algorithm,
                          char *a_directory, char *mode,
                          char *m_directory);

int mcrypt_generic_init(const MCRYPT td, void *key, int lenofkey,
                        void *IV);
void free(void *ptr);
void mcrypt_free(void *ptr);

int mcrypt_enc_get_key_size(const MCRYPT td);
int mcrypt_enc_get_supported_key_sizes(const MCRYPT td, int* len);

int mcrypt_generic_deinit(const MCRYPT td);
int mcrypt_generic_end(const MCRYPT td);
int mdecrypt_generic(MCRYPT td, void *plaintext, int len);
int mcrypt_generic(MCRYPT td, void *plaintext, int len);
int mcrypt_module_close(MCRYPT td);
int mcrypt_enc_mode_has_iv(MCRYPT td);
int mcrypt_enc_get_iv_size(MCRYPT td);
int mcrypt_enc_is_block_mode(MCRYPT td);
int mcrypt_enc_get_block_size(MCRYPT td);
]]

local mcrypt = ffi.load('libmcrypt.so.4')

_M.new = function (self)
    local cipher = 'rijndael-128'
    local mode = 'ecb'

    local c_cipher 	=	ffi_new("char[?]",#cipher+1, cipher)
    local c_mode 	=	ffi_new("char[4]", mode)

    local td = mcrypt.mcrypt_module_open(c_cipher, nil, c_mode, nil)
    return setmetatable( { _td = td }, mt )
end


_M.pass = function (self, key, raw,enc_or_dec)

		local dencrypt	= enc_or_dec
    local iv_len = 8
    local cipher = 'rijndael-128'
    local mode = 'ecb'

    local c_cipher 	=	ffi_new("char[?]",#cipher+1, cipher)
    local c_mode 	=	ffi_new("char[4]", mode)
		local td = mcrypt.mcrypt_module_open(c_cipher, nil, c_mode, nil)

		if  td ==0  then
			ngx.log(ngx.ERR , "mcrypt_module_open failed")
			return nil
		end

    local iv_key =	"1234567890123456";
		local key_len=  #key;
		local data_len=  #raw;

		local block_size, max_key_length, use_key_length, i, count, iv_size;
		--/* Checking for key-length */
		max_key_length = mcrypt.mcrypt_enc_get_key_size(td);
		if  key_len > max_key_length  then
			ngx.log(ngx.ERR , "Size of key is too large for this algorithm key_len:",key_len,",max_key:",max_key_length)
			return nil
		end

		count 	=	ffi_new("int[1]")
		local key_size_tmp = mcrypt.mcrypt_enc_get_supported_key_sizes(td, count);
		local key_length_sizes = ffi.cast("int *",key_size_tmp)

		local key_s	=	nil;

		if count[0] == 0 and key_length_sizes == nil then --/* all lengths 1 - k_l_s = OK */
			use_key_length = key_len;
			key_s = ffi_new("unsigned char[?]",use_key_length,key)
		end

	if  count[0] == 1 then
		key_s = ffi_new("char[?]",key_length_sizes[0])
		ffi.fill(key_s ,use_key_length,0);
		ffi.copy(key_s, key, math.min(key_len, key_length_sizes[0]));
		use_key_length = key_length_sizes[0];
	 else
		use_key_length = max_key_length;

		for i=0,count[0]-1 do
			if  key_length_sizes[i] >= key_len and	key_length_sizes[i] < use_key_length then
				use_key_length = key_length_sizes[i];
			end
		end
		key_s = ffi_new("char[?]",use_key_length)

		ffi.copy(key_s ,key, math.min(key_len,use_key_length));
	end



	if key_length_sizes~=nil then
		mcrypt.mcrypt_free(key_length_sizes);
	end

	local iv_s = nil;
	local  iv_size = mcrypt.mcrypt_enc_get_iv_size (td);

	local has_iv = mcrypt.mcrypt_enc_mode_has_iv(td) ;


	local data_size	=	0;
	local block = mcrypt.mcrypt_enc_is_block_mode(td);
	if  block == 1 then
		block_size =	mcrypt.mcrypt_enc_get_block_size(td);
		data_size = math.floor(((data_len - 1) / block_size) + 1) * block_size;

	else
		data_size = data_len;
	end


	local data_s = ffi_new("char[?]",data_size)
	ffi.fill(data_s ,data_size,0);
	ffi.copy(data_s ,raw ,data_len);

	local ini_ret = mcrypt.mcrypt_generic_init(td, key_s, use_key_length, c_iv)
	if ini_ret < 0 then
		ngx.log(ngx.ERR , "Mcrypt initialisation failed");
		ngx.say(  ini_ret,"ini_ret initialisation failed");
		return nil
	end

 

	if  dencrypt == 1 then
		mcrypt.mcrypt_generic(td, data_s, data_size);
	else
		mcrypt.mdecrypt_generic(td, data_s, data_size);
	end

	local ret_str = ffi_str(data_s,data_size);

	mcrypt.mcrypt_generic_end(td);


	return ret_str
end

_M.encrypt = function (self, key, raw)
	return _M.pass(self, key, raw,1);
end

_M.decrypt = function(self, key, raw)
	return _M.pass(self, key, raw,0);
end

_M.close = function(self)
    local td = self._td
    if td then
        mcrypt.mcrypt_module_close(td)
     end
end

return _M
