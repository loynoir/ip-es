/* eslint-disable no-bitwise */

/* eslint-disable no-plusplus */

/* eslint-disable no-mixed-operators */

/* eslint-disable operator-assignment */
import { Buffer } from 'buffer';
import { networkInterfaces } from 'os';
export const IPES_ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
export const IPES_ipv6Regex = /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

function IPES_isV4Format(ip: string): boolean {
  return IPES_ipv4Regex.test(ip);
}

function IPES_isV6Format(ip: string): boolean {
  return IPES_ipv6Regex.test(ip);
}

function IPES_toBuffer(ip: string, buff?: Buffer, offset?: number): Buffer {
  let _offset = ~~offset;

  let result: Buffer;

  if (IPES_isV4Format(ip)) {
    result = buff || Buffer.alloc(_offset + 4);
    ip.split(/\./g).forEach(byte => {
      result[_offset++] = parseInt(byte, 10) & 0xff;
    });
  } else if (IPES_isV6Format(ip)) {
    const sections = ip.split(':', 8);
    let i: number;

    for (i = 0; i < sections.length; i++) {
      const isv4 = IPES_isV4Format(sections[i]);
      let v4Buffer: Buffer;

      if (isv4) {
        v4Buffer = IPES_toBuffer(sections[i]);
        sections[i] = v4Buffer.slice(0, 2).toString('hex');
      }

      if (v4Buffer && ++i < 8) {
        sections.splice(i, 0, v4Buffer.slice(2, 4).toString('hex'));
      }
    }

    if (sections[0] === '') {
      while (sections.length < 8) sections.unshift('0');
    } else if (sections[sections.length - 1] === '') {
      while (sections.length < 8) sections.push('0');
    } else if (sections.length < 8) {
      for (i = 0; i < sections.length && sections[i] !== ''; i++);

      const argv: Array<number | string> = [i, 1];

      for (i = 9 - sections.length; i > 0; i--) {
        argv.push('0');
      }

      sections.splice.apply(sections, argv);
    }

    result = buff || Buffer.alloc(_offset + 16);

    for (i = 0; i < sections.length; i++) {
      const word = parseInt(sections[i], 16);
      result[_offset++] = word >> 8 & 0xff;
      result[_offset++] = word & 0xff;
    }
  }

  if (!result) {
    throw Error(`Invalid ip address: ${ip}`);
  }

  return result;
}

function IPES_toString(buff: Buffer, offset?: number, length?: number): string {
  const _offset = ~~offset;

  const _length = length || buff.length - _offset;

  const result = [];
  let ret: string;
  let i;

  if (_length === 4) {
    // IPv4
    for (i = 0; i < _length; i++) {
      result.push(buff[_offset + i]);
    }

    ret = result.join('.');
  } else if (_length === 16) {
    // IPv6
    for (i = 0; i < _length; i += 2) {
      result.push(buff.readUInt16BE(_offset + i).toString(16));
    }

    ret = result.join(':');
    ret = ret.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
    ret = ret.replace(/:{3,4}/, '::');
  }

  return ret;
}

function IPES__normalizeFamily(family: string): string {
  return family ? family.toLowerCase() : 'ipv4';
}

function IPES_fromPrefixLen(prefixlen: number, family?: string): string {
  let _prefixlen = prefixlen;

  const _family = _prefixlen > 32 ? 'ipv6' : IPES__normalizeFamily(family);

  let len = 4;

  if (_family === 'ipv6') {
    len = 16;
  }

  const buff = Buffer.alloc(len);

  for (let i = 0, n = buff.length; i < n; ++i) {
    let bits = 8;

    if (_prefixlen < 8) {
      bits = _prefixlen;
    }

    _prefixlen -= bits;
    buff[i] = ~(0xff >> bits) & 0xff;
  }

  return IPES_toString(buff);
}

function IPES_mask(addr: string, mask: string): string {
  const baddr = IPES_toBuffer(addr);
  const bmask = IPES_toBuffer(mask);
  const result = Buffer.alloc(Math.max(baddr.length, bmask.length));
  let i = 0; // Same protocol - do bitwise and

  if (baddr.length === bmask.length) {
    for (i = 0; i < baddr.length; i++) {
      result[i] = baddr[i] & bmask[i];
    }
  } else if (bmask.length === 4) {
    // IPv6 address and IPv4 mask
    // (Mask low bits)
    for (i = 0; i < bmask.length; i++) {
      result[i] = baddr[baddr.length - 4 + i] & bmask[i];
    }
  } else {
    // IPv6 mask and IPv4 addr
    for (i = 0; i < result.length - 6; i++) {
      result[i] = 0;
    } // ::ffff:ipv4


    result[10] = 0xff;
    result[11] = 0xff;

    for (i = 0; i < baddr.length; i++) {
      result[i + 12] = baddr[i] & bmask[i + 12];
    }

    i += 12;
  }

  for (; i < result.length; i++) result[i] = 0;

  return IPES_toString(result);
}

function IPES_cidr(cidrString: string): string {
  const cidrParts = cidrString.split('/');
  const addr = cidrParts[0];
  if (cidrParts.length !== 2) throw new Error(`invalid CIDR subnet: ${addr}`);
  const mask = IPES_fromPrefixLen(parseInt(cidrParts[1], 10));
  return IPES_mask(addr, mask);
}

function IPES_toLong(ip: string): number {
  let ipl = 0;
  ip.split('.').forEach(octet => {
    ipl <<= 8;
    ipl += parseInt(octet, 10);
  });
  return ipl >>> 0;
}

function IPES_fromLong(ipl: number): string {
  return `${ipl >>> 24}.${ipl >> 16 & 255}.${ipl >> 8 & 255}.${ipl & 255}`;
}

function IPES_subnet(addr: string, mask: string) {
  const networkAddress = IPES_toLong(IPES_mask(addr, mask)); // Calculate the mask's length.

  const maskBuffer = IPES_toBuffer(mask);
  let maskLength = 0;

  for (let i = 0; i < maskBuffer.length; i++) {
    if (maskBuffer[i] === 0xff) {
      maskLength += 8;
    } else {
      let octet = maskBuffer[i] & 0xff;

      while (octet) {
        octet = octet << 1 & 0xff;
        maskLength++;
      }
    }
  }

  const numberOfAddresses = 2 ** (32 - maskLength);
  return {
    networkAddress: IPES_fromLong(networkAddress),
    firstAddress: numberOfAddresses <= 2 ? IPES_fromLong(networkAddress) : IPES_fromLong(networkAddress + 1),
    lastAddress: numberOfAddresses <= 2 ? IPES_fromLong(networkAddress + numberOfAddresses - 1) : IPES_fromLong(networkAddress + numberOfAddresses - 2),
    broadcastAddress: IPES_fromLong(networkAddress + numberOfAddresses - 1),
    subnetMask: mask,
    subnetMaskLength: maskLength,
    numHosts: numberOfAddresses <= 2 ? numberOfAddresses : numberOfAddresses - 2,
    length: numberOfAddresses,

    contains(other: string) {
      return networkAddress === IPES_toLong(IPES_mask(other, mask));
    }

  };
}

function IPES_cidrSubnet(cidrString: string) {
  const cidrParts = cidrString.split('/');
  const addr = cidrParts[0];
  if (cidrParts.length !== 2) throw new Error(`invalid CIDR subnet: ${addr}`);
  const mask = IPES_fromPrefixLen(parseInt(cidrParts[1], 10));
  return IPES_subnet(addr, mask);
}

function IPES_not(addr: string): string {
  let i;
  const buff = IPES_toBuffer(addr);

  for (i = 0; i < buff.length; i++) {
    buff[i] = 0xff ^ buff[i];
  }

  return IPES_toString(buff);
}

function IPES_or(a: string, b: string): string {
  let i;
  const ba = IPES_toBuffer(a);
  const bb = IPES_toBuffer(b); // same protocol

  if (ba.length === bb.length) {
    for (i = 0; i < ba.length; ++i) {
      ba[i] |= bb[i];
    }

    return IPES_toString(ba); // mixed protocols
  }

  let buff = ba;
  let other = bb;

  if (bb.length > ba.length) {
    buff = bb;
    other = ba;
  }

  const offset = buff.length - other.length;

  for (i = offset; i < buff.length; ++i) {
    buff[i] |= other[i - offset];
  }

  return IPES_toString(buff);
}

function IPES_isEqual(a: string, b: string): boolean {
  let i;
  let ba = IPES_toBuffer(a);
  let bb = IPES_toBuffer(b); // Same protocol

  if (ba.length === bb.length) {
    for (i = 0; i < ba.length; i++) {
      if (ba[i] !== bb[i]) return false;
    }

    return true;
  } // Swap


  if (bb.length === 4) {
    const t = bb;
    bb = ba;
    ba = t;
  } // a - IPv4, b - IPv6


  for (i = 0; i < 10; i++) {
    if (bb[i] !== 0) return false;
  }

  const word = bb.readUInt16BE(10);
  if (word !== 0 && word !== 0xffff) return false;

  for (i = 0; i < 4; i++) {
    if (ba[i] !== bb[i + 12]) return false;
  }

  return true;
}

function IPES_isPrivate(addr: string): boolean {
  // TODO: maybe :)
  // FIXME: upstream indutny/node-ip version 1.1.5 test fail
  // ref: https://github.com/python/cpython/blob/6c4c11763fad106e43cdcfdbe3bd33ea2765a13f/Lib/ipaddress.py#L1081
  return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^f[cd][0-9a-f]{2}:/i.test(addr) || /^fe80:/i.test(addr) || /^::1$/.test(addr) || /^::$/.test(addr);
}

function IPES_isPublic(addr: string): boolean {
  return !IPES_isPrivate(addr);
}

function IPES_isLoopback(addr: string): boolean {
  return /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/.test(addr) || /^fe80::1$/.test(addr) || /^::1$/.test(addr) || /^::$/.test(addr);
}

function IPES_loopback(family: string): string {
  //
  // Default to `ipv4`
  //
  const _family = IPES__normalizeFamily(family);

  if (_family !== 'ipv4' && _family !== 'ipv6') {
    throw new Error('family must be ipv4 or ipv6');
  }

  return _family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
} //
// ### function address (name, family)
// #### @name {string|'public'|'private'} **Optional** Name or security
//      of the network interface.
// #### @family {ipv4|ipv6} **Optional** IP family of the address (defaults
//      to ipv4).
//
// Returns the address for the network interface on the current system with
// the specified `name`:
//   * String: First `family` address of the interface.
//             If not found see `undefined`.
//   * 'public': the first public ip address of family.
//   * 'private': the first private ip address of family.
//   * undefined: First address with `ipv4` or loopback address `127.0.0.1`.
//


function IPES_address(name?: string, family?: string) {
  const interfaces = networkInterfaces(); //
  // Default to `ipv4`
  //

  const _family = IPES__normalizeFamily(family); //
  // If a specific network interface has been named,
  // return the address.
  //


  if (name && name !== 'private' && name !== 'public') {
    const res = interfaces[name].filter(details => {
      const itemFamily = details.family.toLowerCase();
      return itemFamily === _family;
    });
    if (res.length === 0) return undefined;
    return res[0].address;
  }

  const all = Object.keys(interfaces).map(nic => {
    //
    // Note: name will only be `public` or `private`
    // when this is called.
    //
    const addresses = interfaces[nic].filter(details => {
      const details_family = details.family.toLowerCase();

      if (details_family !== _family || IPES_isLoopback(details.address)) {
        return false;
      }

      if (!name) {
        return true;
      }

      return name === 'public' ? IPES_isPrivate(details.address) : IPES_isPublic(details.address);
    });
    return addresses.length ? addresses[0].address : undefined;
  }).filter(Boolean);
  return !all.length ? IPES_loopback(_family) : all[0];
}

export { IPES_ipv4Regex as ipv4Regex, IPES_ipv6Regex as ipv6Regex, IPES_isV4Format as isV4Format, IPES_isV6Format as isV6Format, IPES_toBuffer as toBuffer, IPES_toString as toString, IPES__normalizeFamily as _normalizeFamily, IPES_fromPrefixLen as fromPrefixLen, IPES_mask as mask, IPES_cidr as cidr, IPES_toLong as toLong, IPES_fromLong as fromLong, IPES_subnet as subnet, IPES_cidrSubnet as cidrSubnet, IPES_not as not, IPES_or as or, IPES_isEqual as isEqual, IPES_isPrivate as isPrivate, IPES_isPublic as isPublic, IPES_isLoopback as isLoopback, IPES_loopback as loopback, IPES_address as address };