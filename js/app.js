var mainModule = angular.module('kodigon', [], function($routeProvider, $locationProvider) {

	$routeProvider.when('/', {
		templateUrl: 'partials/index.html',
		controller: 'indexController'
	});

	$routeProvider.when('/about', {
		templateUrl: 'partials/about.html',
		controller: 'aboutController'
	});

	$routeProvider.when('/algorithm/:name', {
		templateUrl: 'partials/algorithm.html',
		controller: 'algoController'
	});

	$routeProvider.otherwise({redirectTo: '/'});
});


mainModule.factory('utf8', function() {
	return {
		encode: function (input) {

			if (input === null || typeof input === "undefined") {
				return "";
			}

			var input = (input + '');
			var utftext = '',
				start, end, stringl = 0;

			start = end = 0;
			stringl = input.length;
			for (var n = 0; n < stringl; n++) {
				var c1 = input.charCodeAt(n);
				var enc = null;

				if (c1 < 128) {
					end++;
				} else if (c1 > 127 && c1 < 2048) {
					enc = String.fromCharCode((c1 >> 6) | 192, (c1 & 63) | 128);
				} else {
					enc = String.fromCharCode((c1 >> 12) | 224, ((c1 >> 6) & 63) | 128, (c1 & 63) | 128);
				}
				if (enc !== null) {
					if (end > start) {
						utftext += input.slice(start, end);
					}
					utftext += enc;
					start = end = n + 1;
				}
			}

			if (end > start) {
				utftext += input.slice(start, stringl);
			}

			return utftext;
		}
	};
});


mainModule.factory('base64', ['$window', function($window) {
	return {

		name: 'Base64',
		readonly: false,

		encode: function(input) {
			return $window.btoa(input);
		},

		decode: function(input) {
			return $window.atob(input);
		}

	};
}]);


mainModule.factory('escape', ['$window', function($window) {
	return {

		name: 'Escape',
		readonly: false,

		encode: function(input) {
			return $window.encodeURI(input);
		},

		decode: function(input) {
			return $window.decodeURI(input);
		}

	};
}]);


mainModule.factory('urlencode', ['$window', function($window) {
	return {

		name: 'URL Encode',
		readonly: false,

		encode: function(input) {
			return $window.encodeURIComponent(input);
		},

		decode: function(input) {
			return $window.decodeURIComponent(input);
		}

	};
}]);


mainModule.factory('htmlentities', ['$window', function($window) {
	return {

		name: 'HTML Entities',
		readonly: false,

		encode: function(input) {
			return input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

		},

		decode: function(input) {
			return input.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
		}

	};
}]);


mainModule.factory('sha256', ['utf8', function(utf8) {
	return {

		name: 'SHA256',
		readonly: true,

		encode: function(input) {
			var chrsz = 8;
			var hexcase = 0;

			function safe_add (x, y) {
				var lsw = (x & 0xFFFF) + (y & 0xFFFF);
				var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
				return (msw << 16) | (lsw & 0xFFFF);
			}

			function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
			function R (X, n) { return ( X >>> n ); }
			function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
			function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
			function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
			function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
			function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
			function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }

			function core_sha256 (m, l) {
				var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
				var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
				var W = new Array(64);
				var a, b, c, d, e, f, g, h, i, j;
				var T1, T2;

				m[l >> 5] |= 0x80 << (24 - l % 32);
				m[((l + 64 >> 9) << 4) + 15] = l;

				for ( var i = 0; i<m.length; i+=16 ) {
					a = HASH[0];
					b = HASH[1];
					c = HASH[2];
					d = HASH[3];
					e = HASH[4];
					f = HASH[5];
					g = HASH[6];
					h = HASH[7];

					for ( var j = 0; j<64; j++) {
						if (j < 16) W[j] = m[j + i];
						else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);

						T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
						T2 = safe_add(Sigma0256(a), Maj(a, b, c));

						h = g;
						g = f;
						f = e;
						e = safe_add(d, T1);
						d = c;
						c = b;
						b = a;
						a = safe_add(T1, T2);
					}

					HASH[0] = safe_add(a, HASH[0]);
					HASH[1] = safe_add(b, HASH[1]);
					HASH[2] = safe_add(c, HASH[2]);
					HASH[3] = safe_add(d, HASH[3]);
					HASH[4] = safe_add(e, HASH[4]);
					HASH[5] = safe_add(f, HASH[5]);
					HASH[6] = safe_add(g, HASH[6]);
					HASH[7] = safe_add(h, HASH[7]);
				}
				return HASH;
			}

			function str2binb (str) {
				var bin = Array();
				var mask = (1 << chrsz) - 1;
				for(var i = 0; i < str.length * chrsz; i += chrsz) {
					bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
				}
				return bin;
			}

			function Utf8Encode(string) {
				string = string.replace(/\r\n/g,"\n");
				var utftext = "";

				for (var n = 0; n < string.length; n++) {

					var c = string.charCodeAt(n);

					if (c < 128) {
						utftext += String.fromCharCode(c);
					}
					else if((c > 127) && (c < 2048)) {
						utftext += String.fromCharCode((c >> 6) | 192);
						utftext += String.fromCharCode((c & 63) | 128);
					}
					else {
						utftext += String.fromCharCode((c >> 12) | 224);
						utftext += String.fromCharCode(((c >> 6) & 63) | 128);
						utftext += String.fromCharCode((c & 63) | 128);
					}

				}

				return utftext;
			}

			function binb2hex (binarray) {
				var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
				var str = "";
				for(var i = 0; i < binarray.length * 4; i++) {
					str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
					hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
				}
				return str;
			}

			input = utf8.encode(input);
			return binb2hex(core_sha256(str2binb(input), input.length * chrsz));
		}
	};
}]);


mainModule.factory('cr32', ['utf8', function(utf8) {
	return {

		name: 'CR32',
		readonly: true,

		encode: function(input) {
			input = utf8.encode(input);
			var table = "00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F 30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D";

			var crc = 0;
			var x = 0;
			var y = 0;

			crc = crc ^ (-1);
			for (var i = 0, iTop = input.length; i < iTop; i++) {
				y = (crc ^ input.charCodeAt(i)) & 0xFF;
				x = "0x" + table.substr(y * 9, 8);
				crc = (crc >>> 8) ^ x;
			}

			return crc ^ (-1);
		}
	};
}]);


mainModule.factory('sha1', function() {
	return {

		name: 'SHA1',
		readonly: true,

		encode: function(input) {
			function rotate_left(n,s) {
				var t4 = ( n<<s ) | (n>>>(32-s));
				return t4;
			};

			function lsb_hex(val) {
				var str="";
				var i;
				var vh;
				var vl;

				for( i=0; i<=6; i+=2 ) {
					vh = (val>>>(i*4+4))&0x0f;
					vl = (val>>>(i*4))&0x0f;
					str += vh.toString(16) + vl.toString(16);
				}
				return str;
			};

			function cvt_hex(val) {
				var str="";
				var i;
				var v;

				for( i=7; i>=0; i-- ) {
					v = (val>>>(i*4))&0x0f;
					str += v.toString(16);
				}
				return str;
			};


			function Utf8Encode(input) {
				input = input.replace(/\r\n/g,"\n");
				var utftext = "";

				for (var n = 0; n < input.length; n++) {

					var c = input.charCodeAt(n);

					if (c < 128) {
						utftext += String.fromCharCode(c);
					}
					else if((c > 127) && (c < 2048)) {
						utftext += String.fromCharCode((c >> 6) | 192);
						utftext += String.fromCharCode((c & 63) | 128);
					}
					else {
						utftext += String.fromCharCode((c >> 12) | 224);
						utftext += String.fromCharCode(((c >> 6) & 63) | 128);
						utftext += String.fromCharCode((c & 63) | 128);
					}

				}

				return utftext;
			};

			var blockstart;
			var i, j;
			var W = new Array(80);
			var H0 = 0x67452301;
			var H1 = 0xEFCDAB89;
			var H2 = 0x98BADCFE;
			var H3 = 0x10325476;
			var H4 = 0xC3D2E1F0;
			var A, B, C, D, E;
			var temp;

			input = Utf8Encode(input);

			var input_len = input.length;

			var word_array = new Array();
			for( i=0; i<input_len-3; i+=4 ) {
				j = input.charCodeAt(i)<<24 | input.charCodeAt(i+1)<<16 |
				input.charCodeAt(i+2)<<8 | input.charCodeAt(i+3);
				word_array.push( j );
			}

			switch( input_len % 4 ) {
				case 0:
					i = 0x080000000;
				break;
				case 1:
					i = input.charCodeAt(input_len-1)<<24 | 0x0800000;
				break;

				case 2:
					i = input.charCodeAt(input_len-2)<<24 | input.charCodeAt(input_len-1)<<16 | 0x08000;
				break;

				case 3:
					i = input.charCodeAt(input_len-3)<<24 | input.charCodeAt(input_len-2)<<16 | input.charCodeAt(input_len-1)<<8	| 0x80;
				break;
			}

			word_array.push( i );

			while( (word_array.length % 16) != 14 ) word_array.push( 0 );

			word_array.push( input_len>>>29 );
			word_array.push( (input_len<<3)&0x0ffffffff );


			for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {

				for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
				for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

				A = H0;
				B = H1;
				C = H2;
				D = H3;
				E = H4;

				for( i= 0; i<=19; i++ ) {
					temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
					E = D;
					D = C;
					C = rotate_left(B,30);
					B = A;
					A = temp;
				}

				for( i=20; i<=39; i++ ) {
					temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
					E = D;
					D = C;
					C = rotate_left(B,30);
					B = A;
					A = temp;
				}

				for( i=40; i<=59; i++ ) {
					temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
					E = D;
					D = C;
					C = rotate_left(B,30);
					B = A;
					A = temp;
				}

				for( i=60; i<=79; i++ ) {
					temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
					E = D;
					D = C;
					C = rotate_left(B,30);
					B = A;
					A = temp;
				}

				H0 = (H0 + A) & 0x0ffffffff;
				H1 = (H1 + B) & 0x0ffffffff;
				H2 = (H2 + C) & 0x0ffffffff;
				H3 = (H3 + D) & 0x0ffffffff;
				H4 = (H4 + E) & 0x0ffffffff;
			}

			var temp = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);

			return temp.toLowerCase();
		}
	};
});


mainModule.factory('md5', function() {
	return {

		name: 'MD5',
		readonly: true,

		encode: function(input) {
			function RotateLeft(lValue, iShiftBits) {
				return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
			}
		
			function AddUnsigned(lX,lY) {
				var lX4,lY4,lX8,lY8,lResult;
				lX8 = (lX & 0x80000000);
				lY8 = (lY & 0x80000000);
				lX4 = (lX & 0x40000000);
				lY4 = (lY & 0x40000000);
				lResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
				if (lX4 & lY4) {
					return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
				}
				if (lX4 | lY4) {
					if (lResult & 0x40000000) {
						return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
					} else {
						return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
					}
				} else {
					return (lResult ^ lX8 ^ lY8);
				}
			}
		
			function F(x,y,z) { return (x & y) | ((~x) & z); }
			function G(x,y,z) { return (x & z) | (y & (~z)); }
			function H(x,y,z) { return (x ^ y ^ z); }
			function I(x,y,z) { return (y ^ (x | (~z))); }
		
			function FF(a,b,c,d,x,s,ac) {
				a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
				return AddUnsigned(RotateLeft(a, s), b);
			};
		
			function GG(a,b,c,d,x,s,ac) {
				a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
				return AddUnsigned(RotateLeft(a, s), b);
			};
		
			function HH(a,b,c,d,x,s,ac) {
				a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
				return AddUnsigned(RotateLeft(a, s), b);
			};
		
			function II(a,b,c,d,x,s,ac) {
				a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
				return AddUnsigned(RotateLeft(a, s), b);
			};
		
			function ConvertToWordArray(input) {
				var lWordCount;
				var lMessageLength = input.length;
				var lNumberOfWords_temp1=lMessageLength + 8;
				var lNumberOfWords_temp2=(lNumberOfWords_temp1-(lNumberOfWords_temp1 % 64))/64;
				var lNumberOfWords = (lNumberOfWords_temp2+1)*16;
				var lWordArray=Array(lNumberOfWords-1);
				var lBytePosition = 0;
				var lByteCount = 0;
				while ( lByteCount < lMessageLength ) {
					lWordCount = (lByteCount-(lByteCount % 4))/4;
					lBytePosition = (lByteCount % 4)*8;
					lWordArray[lWordCount] = (lWordArray[lWordCount] | (input.charCodeAt(lByteCount)<<lBytePosition));
					lByteCount++;
				}
				lWordCount = (lByteCount-(lByteCount % 4))/4;
				lBytePosition = (lByteCount % 4)*8;
				lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80<<lBytePosition);
				lWordArray[lNumberOfWords-2] = lMessageLength<<3;
				lWordArray[lNumberOfWords-1] = lMessageLength>>>29;
				return lWordArray;
			};
		
			function WordToHex(lValue) {
				var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
				for (lCount = 0;lCount<=3;lCount++) {
					lByte = (lValue>>>(lCount*8)) & 255;
					WordToHexValue_temp = "0" + lByte.toString(16);
					WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
				}
				return WordToHexValue;
			};
		
			function Utf8Encode(input) {
				input = input.replace(/\r\n/g,"\n");
				var utftext = "";
		
				for (var n = 0; n < input.length; n++) {
		
					var c = input.charCodeAt(n);
		
					if (c < 128) {
						utftext += String.fromCharCode(c);
					}
					else if((c > 127) && (c < 2048)) {
						utftext += String.fromCharCode((c >> 6) | 192);
						utftext += String.fromCharCode((c & 63) | 128);
					}
					else {
						utftext += String.fromCharCode((c >> 12) | 224);
						utftext += String.fromCharCode(((c >> 6) & 63) | 128);
						utftext += String.fromCharCode((c & 63) | 128);
					}
		
				}
		
				return utftext;
			};
		
			var x=Array();
			var k,AA,BB,CC,DD,a,b,c,d;
			var S11=7, S12=12, S13=17, S14=22;
			var S21=5, S22=9 , S23=14, S24=20;
			var S31=4, S32=11, S33=16, S34=23;
			var S41=6, S42=10, S43=15, S44=21;
		
			input = Utf8Encode(input);
		
			x = ConvertToWordArray(input);
		
			a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
		
			for (k=0;k<x.length;k+=16) {
				AA=a; BB=b; CC=c; DD=d;
				a=FF(a,b,c,d,x[k+0], S11,0xD76AA478);
				d=FF(d,a,b,c,x[k+1], S12,0xE8C7B756);
				c=FF(c,d,a,b,x[k+2], S13,0x242070DB);
				b=FF(b,c,d,a,x[k+3], S14,0xC1BDCEEE);
				a=FF(a,b,c,d,x[k+4], S11,0xF57C0FAF);
				d=FF(d,a,b,c,x[k+5], S12,0x4787C62A);
				c=FF(c,d,a,b,x[k+6], S13,0xA8304613);
				b=FF(b,c,d,a,x[k+7], S14,0xFD469501);
				a=FF(a,b,c,d,x[k+8], S11,0x698098D8);
				d=FF(d,a,b,c,x[k+9], S12,0x8B44F7AF);
				c=FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1);
				b=FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
				a=FF(a,b,c,d,x[k+12],S11,0x6B901122);
				d=FF(d,a,b,c,x[k+13],S12,0xFD987193);
				c=FF(c,d,a,b,x[k+14],S13,0xA679438E);
				b=FF(b,c,d,a,x[k+15],S14,0x49B40821);
				a=GG(a,b,c,d,x[k+1], S21,0xF61E2562);
				d=GG(d,a,b,c,x[k+6], S22,0xC040B340);
				c=GG(c,d,a,b,x[k+11],S23,0x265E5A51);
				b=GG(b,c,d,a,x[k+0], S24,0xE9B6C7AA);
				a=GG(a,b,c,d,x[k+5], S21,0xD62F105D);
				d=GG(d,a,b,c,x[k+10],S22,0x2441453);
				c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681);
				b=GG(b,c,d,a,x[k+4], S24,0xE7D3FBC8);
				a=GG(a,b,c,d,x[k+9], S21,0x21E1CDE6);
				d=GG(d,a,b,c,x[k+14],S22,0xC33707D6);
				c=GG(c,d,a,b,x[k+3], S23,0xF4D50D87);
				b=GG(b,c,d,a,x[k+8], S24,0x455A14ED);
				a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905);
				d=GG(d,a,b,c,x[k+2], S22,0xFCEFA3F8);
				c=GG(c,d,a,b,x[k+7], S23,0x676F02D9);
				b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
				a=HH(a,b,c,d,x[k+5], S31,0xFFFA3942);
				d=HH(d,a,b,c,x[k+8], S32,0x8771F681);
				c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122);
				b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
				a=HH(a,b,c,d,x[k+1], S31,0xA4BEEA44);
				d=HH(d,a,b,c,x[k+4], S32,0x4BDECFA9);
				c=HH(c,d,a,b,x[k+7], S33,0xF6BB4B60);
				b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
				a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6);
				d=HH(d,a,b,c,x[k+0], S32,0xEAA127FA);
				c=HH(c,d,a,b,x[k+3], S33,0xD4EF3085);
				b=HH(b,c,d,a,x[k+6], S34,0x4881D05);
				a=HH(a,b,c,d,x[k+9], S31,0xD9D4D039);
				d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5);
				c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8);
				b=HH(b,c,d,a,x[k+2], S34,0xC4AC5665);
				a=II(a,b,c,d,x[k+0], S41,0xF4292244);
				d=II(d,a,b,c,x[k+7], S42,0x432AFF97);
				c=II(c,d,a,b,x[k+14],S43,0xAB9423A7);
				b=II(b,c,d,a,x[k+5], S44,0xFC93A039);
				a=II(a,b,c,d,x[k+12],S41,0x655B59C3);
				d=II(d,a,b,c,x[k+3], S42,0x8F0CCC92);
				c=II(c,d,a,b,x[k+10],S43,0xFFEFF47D);
				b=II(b,c,d,a,x[k+1], S44,0x85845DD1);
				a=II(a,b,c,d,x[k+8], S41,0x6FA87E4F);
				d=II(d,a,b,c,x[k+15],S42,0xFE2CE6E0);
				c=II(c,d,a,b,x[k+6], S43,0xA3014314);
				b=II(b,c,d,a,x[k+13],S44,0x4E0811A1);
				a=II(a,b,c,d,x[k+4], S41,0xF7537E82);
				d=II(d,a,b,c,x[k+11],S42,0xBD3AF235);
				c=II(c,d,a,b,x[k+2], S43,0x2AD7D2BB);
				b=II(b,c,d,a,x[k+9], S44,0xEB86D391);
				a=AddUnsigned(a,AA);
				b=AddUnsigned(b,BB);
				c=AddUnsigned(c,CC);
				d=AddUnsigned(d,DD);
			}
		
			var temp = WordToHex(a)+WordToHex(b)+WordToHex(c)+WordToHex(d);
		
			return temp.toLowerCase();
		}
	};
});


mainModule.factory('algorithms', function() {
	return {

		list: [
			{
				id: 'escape',
				name: 'Escape',
				notyet: true
			},
			{
				id: 'htmlentities',
				name: 'HtmlEntities',
				notyet: false
			},
			{
				id: 'urlencode',
				name: 'URLencode',
				notyet: false
			},
			{
				id: 'base64',
				name: 'Base64',
				notyet: false
			},
			{
				id: 'md5',
				name: 'MD5',
				notyet: false
			},
			{
				id: 'sha1',
				name: 'SHA1',
				notyet: false
			},
			{
				id: 'sha256',
				name: 'SHA256',
				notyet: false
			},
			{
				id: 'gost',
				name: 'Gost',
				notyet: true
			},
			{
				id: 'cr32',
				name: 'CR32',
				notyet: false
			},
			{
				id: 'whirlpool',
				name: 'Whirlpool',
				notyet: true
			},
			{
				id: 'ripemd128',
				name: 'Ripemd128',
				notyet: true
			},
			{
				id: 'snefru',
				name: 'Snefru',
				notyet: true
			}
		]
	};
});


var appController = function($scope, $location) {
	$scope.location = $location;
	$scope.algoLocation = new RegExp('^/algorithm');
};

appController.$inject = ['$scope', '$location'];


var indexController = function($scope, algorithms) {
	$scope.algorithms = algorithms.list;
};

indexController.$inject = ['$scope', 'algorithms'];


var aboutController = function($scope, algorithms) {
	$scope.algorithms = algorithms.list;
};

aboutController.$inject = ['$scope', 'algorithms'];


var algoController = function($scope, $route, $routeParams, $location, base64, md5, sha1, cr32, urlencode, htmlentities, sha256) {

	var algo;

	switch($routeParams.name){
		case 'base64':
			algo = base64;
			break;
		case 'md5':
			algo = md5;
			break;
		case 'sha1':
			algo = sha1;
			break;
		case 'cr32':
			algo = cr32;
			break;
		case 'urlencode':
			algo = urlencode;
			break;
		case 'htmlentities':
			algo = htmlentities;
			break;
		case 'sha256':
			algo = sha256;
			break;
		default:
			algo = base64;
			break;
	}

	$scope.readonly = algo.readonly;
	$scope.name = algo.name;

	$scope.change = function(text, encoded) {
		if(encoded && !$scope.readonly)
			$scope.raw = algo.decode($scope.encoded);
		else
			$scope.encoded = algo.encode($scope.raw);
	}
};

algoController.$inject = ['$scope', '$route', '$routeParams', '$location', 'base64', 'md5', 'sha1', 'cr32', 'urlencode', 'htmlentities', 'sha256'];