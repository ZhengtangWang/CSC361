"""
Name: Raymond Wang
ID:	  V00802086
Date: JAN 26, 2018
"""

import socket
import sys
import ssl


def main():
    if len(sys.argv) != 2:
        print("INVALID INPUT")
        return
    print('\nWebsite: ' + sys.argv[1])
    ip_address = socket.gethostbyname(socket.getfqdn(sys.argv[1]))  # Get IP address
    print('IP: ' + ip_address)
    address = (ip_address, 443)  # HTTPS
    try:
        sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))  # Wrap the socket
        sock.settimeout(1)
        if sock.connect(address) != socket.error:  # Check for HTTPS support
            print('Support of HTTPS: YES')
            https = True
            sock.close()
    except Exception as e:
        print('Support of HTTPS: NO ', e)  # Not support HTTPS
        https = False

    try:
        context = get_http2_ssl_context()
        connection = establish_tcp_connection(sys.argv[1])
        negotiate_tls(connection, context, sys.argv[1])
        print('The newest HTTP versions that the web server supports: HTTP/2')
        support_http2 = True
    except Exception as e:
        support_http2 = False

    if https:
        print('Connecting over port 443...\n')
        port443(ip_address, support_http2)
    else:
        print('Connecting over port 80...\n')
        port80(ip_address, support_http2)


def port80(ip_address, support_http2):
    s = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        address = (ip_address, 80)  # HTTP
        sock.connect(address)  # Connect to HTTP address
        count = sock.sendall(bytes('GET / HTTP/1.1\r\nHost: ' + sys.argv[1] + '\r\nConnection: keep-alive\r\n\r\n',
                                   'utf8'))  # GET request
        if count == 0:  # If failed to send
            print('Failed to check HTTP')
        buf = sock.recv(1024)  # Receiving response
        while len(buf):
            s = s + bytes.decode(buf)
            buf = sock.recv(1024)
    except Exception as e:
        sock.close()

    count = 0
    while True:
        index = s.find('\n')
        if index == -1:
            s2 = s
        else:
            s2 = s[:index]
        if len(s2) == 0 or s2[0] == '\r':
            break
        if s2.find('HTTP') == 0:  # Checking HTTP version
            if not support_http2:  # If not HTTP/2
                print('The newest HTTP versions that the web server supports: ' + s2[:8])
            s7 = s2[9:12]
            if s7 == '505':  # Check status code
                print('Status code: ' + s7 + ' - HTTP version not supported')
            if s7 == '404':
                print('Status code: ' + s7 + ' - File not found')
            if s7 == '301':
                print('Status code: ' + s7 + ' - Moved permanently')
                print('Redirecting to new location... (over port 443)\n')
                port443(ip_address, support_http2)  # port443 to new location
                break
            if s7 == '302':
                print('Status code: ' + s7 + ' - Found')
                print('Redirecting to new location... (over port 443)\n')
                port443(ip_address, support_http2)  # port443 to new location
                break
            if s7 == '200':
                print('Status code: ' + s7 + ' - OK')
            else:
                print('Status code: ' + s7)

        if s2.find('Set-Cookie') == 0:  # Check if contain Set-Cookie
            s3 = s2[12:]
            index2 = s3.find('=')
            key = s3[:index2]  # Get Set-Cookie key
            s3 = s3[index2 + 1:]
            index3 = s3.find(';')
            domain = ''  # domain value
            if index3 != -1:
                index4 = s3.find('domain=')  # Get domain
                if index4 != -1:
                    domain = s3[index4 + 7:]
                    index5 = domain.find(';')
                    domain = s3[index4 + 7:index5]
            if count == 0:  # First time received this Set-Cookie
                print('List of Cookies:	')
                count = count + 1
            print('* name: ' + key + ', domain name: ' + domain)
        if index == -1:  # String end, break
            break
        s = s[index + 1:]  # Delete this row


def port443(ip_address, support_http2):
    a = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = ssl.wrap_socket(sock)  # Wrap with SSL
        sock.settimeout(1)
        address = (ip_address, 443)  # HTTPS
        sock.connect(address)
        count = sock.sendall(bytes('GET / HTTP/1.1\r\nHost: ' + sys.argv[1] + '\r\nConnection: keep-alive\r\n\r\n',
                                   'utf8'))  # GET request
        if count == 0:  # If failed to send
            print('Failed to check HTTP')
        buf = sock.recv(1024)  # Receiving response
        while len(buf):
            a = a + bytes.decode(buf)
            buf = sock.recv(1024)
    except Exception as e:
        sock.close()

    count = 0
    while True:
        index = a.find('\n')
        if index == -1:
            s2 = a
        else:
            s2 = a[:index]
        if len(s2) == 0 or s2[0] == '\r':
            break
        if s2.find('HTTP') == 0:  # Checking HTTP version
            if not support_http2:
                print('The newest HTTP versions that the web server supports: ' + s2[:8])
            s7 = s2[9:12]
            if s7 == '505':  # Check status code
                print('Status code: ' + s7 + ' - HTTP version not supported')
            if s7 == '404':
                print('Status code: ' + s7 + ' - File not found')
            if s7 == '301':
                print('Status code: ' + s7 + ' - Moved permanently')
                print('Redirecting to new location... (over port 80)\n')
                port80(ip_address, support_http2)  # port443 to new location
                break
            if s7 == '302':
                print('Status code: ' + s7 + ' - Found')
                print('Redirecting to new location... (over port 80)\n')
                port80(ip_address, support_http2)  # port443 to new location
                break
            if s7 == '200':
                print('Status code: ' + s7 + ' - OK')
            else:
                print('Status code: ' + s7)
        if s2.find('Set-Cookie') == 0:  # Check if contain Set-Cookie
            s3 = s2[12:]
            index2 = s3.find('=')
            key = s3[:index2]  # Get Set-Cookie key
            s3 = s3[index2 + 1:]
            index3 = s3.find(';')
            domain = ''  # domain value
            if index3 != -1:
                index4 = s3.find('domain=')  # Get domain
                if index4 != -1:
                    domain = s3[index4 + 7:]
            if count == 0:  # First time received this Set-Cookie
                print('List of Cookies:	')
                count = count + 1
            print('* name: ' + key + ', domain name: ' + domain)
        if index == -1:  # String end, break
            break
        a = a[index + 1:]  # Delete this row


def establish_tcp_connection(host):
    return socket.create_connection((host, 443))


def get_http2_ssl_context():
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    ctx.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )

    ctx.options |= ssl.OP_NO_COMPRESSION

    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    try:
        ctx.set_npn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    return ctx


def negotiate_tls(tcp_conn, context, host):
    tls_conn = context.wrap_socket(tcp_conn, server_hostname=host)

    negotiated_protocol = tls_conn.selected_alpn_protocol()
    if negotiated_protocol is None:
        negotiated_protocol = tls_conn.selected_npn_protocol()

    if negotiated_protocol != "h2":
        raise RuntimeError("Didn't negotiate HTTP/2!")

    return tls_conn


if __name__ == '__main__':
    main()
    print('\n')
