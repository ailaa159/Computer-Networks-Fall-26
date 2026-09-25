import socket
import struct
import random

DNS_PORT = 53
TIMEOUT = 3 
TYPES = {1: "A", 2: "NS", 5: "CNAME", 28: "AAAA"}

RCODES = {0: "NOERROR", 1: "FORMERR (format error)", 2: "SERVFAIL (server failure)",
          3: "NXDOMAIN (domain does not exist)", 4: "NOTIMP (not implemented)",
          5: "REFUSED (query refused)"}


def is_valid_domain(domain):
    if len(domain) == 0 or len(domain) > 253:
        return False
    for part in domain.split("."):
        if len(part) == 0 or len(part) > 63:
            return False
        if not part.replace("-", "").isalnum() or not part.isascii():
            return False
    return True


def build_query(domain, trans_id):
    header = struct.pack("!HHHHHH", trans_id, 0x0100, 1, 0, 0, 0)

    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"

    question = qname + struct.pack("!HH", 1, 1)
    return header + question

def read_name(data, pos):
    labels = []
    jumped = False
    return_pos = pos
    jumps = 0

    while True:
        length = data[pos]
        if length >= 0xC0:                      
            if not jumped:
                return_pos = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            jumped = True
            jumps += 1
            if jumps > 20:
                raise ValueError("bad name pointers in response")
        elif length == 0:                      
            if not jumped:
                return_pos = pos + 1
            break
        else:                                   
            labels.append(data[pos + 1: pos + 1 + length].decode())
            pos += 1 + length

    return ".".join(labels), return_pos

def parse_response(data, trans_id):
    if len(data) < 12:
        raise ValueError("response too short")

    r_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if r_id != trans_id:
        raise ValueError("transaction ID does not match")

    qr = (flags >> 15) & 1
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    print("\n--- DNS Response ---")
    print("Transaction ID :", hex(r_id))
    print("Flags          :", hex(flags))
    print("  QR =", qr, "(response)" if qr else "(query)")
    print("  AA =", aa, " TC =", tc, " RD =", rd, " RA =", ra)
    print("  RCODE =", rcode, RCODES.get(rcode, "unknown"))
    print("Questions:", qdcount, " Answers:", ancount)

    pos = 12
    for i in range(qdcount):
        name, pos = read_name(data, pos)
        qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        print("Query Name     :", name)
        print("Query Type     :", TYPES.get(qtype, qtype))

    if rcode != 0:
        print("Lookup failed:", RCODES.get(rcode, "unknown error"))
        return

    found_ip = False
    print("\nAnswer Records:")
    for i in range(ancount):
        name, pos = read_name(data, pos)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        rdata_pos = pos
        pos += rdlength

        if rtype == 1:                              
            ip = ".".join(str(b) for b in data[rdata_pos:rdata_pos + 4])
            print(f"  {name}  A  {ip}  TTL={ttl}s")
            found_ip = True
        elif rtype == 5:                            
            alias, _ = read_name(data, rdata_pos)
            print(f"  {name}  CNAME  {alias}  TTL={ttl}s")
        else:
            print(f"  {name}  type {rtype}  TTL={ttl}s")

    if not found_ip:
        print("No IPv4 (A) address found in the answer.")


def dns_lookup(domain, server):
    trans_id = random.randint(0, 65535)
    query = build_query(domain, trans_id)

    print("\n--- DNS Query ---")
    print("DNS Server     :", server, "port", DNS_PORT)
    print("Domain         :", domain)
    print("Transaction ID :", hex(trans_id))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(query, (server, DNS_PORT))
        data, addr = sock.recvfrom(512)
        parse_response(data, trans_id)
    except socket.timeout:
        print("Error: request timed out (no reply from server)")
    except (ValueError, IndexError, struct.error) as e:
        print("Error: invalid/malformed response -", e)
    except OSError as e:
        print("Network error:", e)
    finally:
        sock.close()


def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or int(p) > 255:
            return False
    return True


def main():
    server = input("Enter DNS server IP (e.g. 8.8.8.8): ").strip()
    while not is_valid_ip(server):
        server = input("Invalid IP, enter again (e.g. 8.8.8.8): ").strip()

    while True:
        try:
            domain = input("\nEnter domain name (or 'quit'): ").strip().rstrip(".")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break
        if domain.lower() == "quit":
            break
        if not is_valid_domain(domain):
            print("Invalid domain name, try again.")
            continue
        dns_lookup(domain, server)


main()