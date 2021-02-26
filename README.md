# IP-ES

IP address utilities for node.js, support cjs/esm/ts.

# Feature
1. CJS support
```js
const ip = require('ip-es');
ip.address();
```

2. ESM support. Now enjoy tree shaking. :)
```js
import {address} from 'ip-es/lib/es';
address();
```

3. Typescript support. Now your editor may give you annotation hints. :)

# Current Limitations
One and only one upstream [bug](https://github.com/indutny/node-ip/issues/107) not pass mocha test.


# Fork Goal
[x] Add ESM support, now enjoy tree shaking :)

[x] While add ESM support, also typescript support! :)

[] Add some esm support to `buffer-browserify-es` and `os-browserify-es`, then `ip-browserify`

[] Port python's [ipaddress](https://github.com/python/cpython/blob/6c4c11763fad106e43cdcfdbe3bd33ea2765a13f/Lib/ipaddress.py#L1081) to fix issue107. Maybe :(


# Credit
Original [repo](https://github.com/indutny/node-ip)


## Installation

###  npm
npm install https://github.com/loynoir/ip-es

  
## Usage
Get your ip address, compare ip addresses, validate ip addresses, etc.

# The CJS WAY
```js
var ip = require('ip-es');

ip.address() // my ip address
ip.isEqual('::1', '::0:1'); // true
ip.toBuffer('127.0.0.1') // Buffer([127, 0, 0, 1])
ip.toString(new Buffer([127, 0, 0, 1])) // 127.0.0.1
ip.fromPrefixLen(24) // 255.255.255.0
ip.mask('192.168.1.134', '255.255.255.0') // 192.168.1.0
ip.cidr('192.168.1.134/26') // 192.168.1.128
ip.not('255.255.255.0') // 0.0.0.255
ip.or('192.168.1.134', '0.0.0.255') // 192.168.1.255
ip.isPrivate('127.0.0.1') // true
ip.isV4Format('127.0.0.1'); // true
ip.isV6Format('::ffff:127.0.0.1'); // true

// operate on buffers in-place
var buf = new Buffer(128);
var offset = 64;
ip.toBuffer('127.0.0.1', buf, offset);  // [127, 0, 0, 1] at offset 64
ip.toString(buf, offset, 4);            // '127.0.0.1'

// subnet information
ip.subnet('192.168.1.134', '255.255.255.192')
// { networkAddress: '192.168.1.128',
//   firstAddress: '192.168.1.129',
//   lastAddress: '192.168.1.190',
//   broadcastAddress: '192.168.1.191',
//   subnetMask: '255.255.255.192',
//   subnetMaskLength: 26,
//   numHosts: 62,
//   length: 64,
//   contains: function(addr){...} }
ip.cidrSubnet('192.168.1.134/26')
// Same as previous.

// range checking
ip.cidrSubnet('192.168.1.134/26').contains('192.168.1.190') // true


// ipv4 long conversion
ip.toLong('127.0.0.1'); // 2130706433
ip.fromLong(2130706433); // '127.0.0.1'
```


# The ESM WAY
```js
from ip from 'ip-es';

ip.address() // my ip address
ip.isEqual('::1', '::0:1'); // true
ip.toBuffer('127.0.0.1') // Buffer([127, 0, 0, 1])
ip.toString(new Buffer([127, 0, 0, 1])) // 127.0.0.1
ip.fromPrefixLen(24) // 255.255.255.0
ip.mask('192.168.1.134', '255.255.255.0') // 192.168.1.0
ip.cidr('192.168.1.134/26') // 192.168.1.128
ip.not('255.255.255.0') // 0.0.0.255
ip.or('192.168.1.134', '0.0.0.255') // 192.168.1.255
ip.isPrivate('127.0.0.1') // true
ip.isV4Format('127.0.0.1'); // true
ip.isV6Format('::ffff:127.0.0.1'); // true

// operate on buffers in-place
var buf = new Buffer(128);
var offset = 64;
ip.toBuffer('127.0.0.1', buf, offset);  // [127, 0, 0, 1] at offset 64
ip.toString(buf, offset, 4);            // '127.0.0.1'

// subnet information
ip.subnet('192.168.1.134', '255.255.255.192')
// { networkAddress: '192.168.1.128',
//   firstAddress: '192.168.1.129',
//   lastAddress: '192.168.1.190',
//   broadcastAddress: '192.168.1.191',
//   subnetMask: '255.255.255.192',
//   subnetMaskLength: 26,
//   numHosts: 62,
//   length: 64,
//   contains: function(addr){...} }
ip.cidrSubnet('192.168.1.134/26')
// Same as previous.

// range checking
ip.cidrSubnet('192.168.1.134/26').contains('192.168.1.190') // true


// ipv4 long conversion
ip.toLong('127.0.0.1'); // 2130706433
ip.fromLong(2130706433); // '127.0.0.1'
```
