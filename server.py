import socket
import threading
import sys

def listen(addr, fname):
    BUFFER_SIZE = 1024  # Normally 1024, but we want fast response

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((addr))
    s.listen(1)

    while True:

        data = []

        conn, addr = s.accept()
        data.append(str(addr))
        data.append(' ')
        while 1:
            rx = conn.recv(BUFFER_SIZE).decode()
            data.append(rx)
            if not rx:
                break
            conn.send(b'OK\n')  # echo

        data.append('\n')

        with open(fname, 'a') as f:
            f.write("".join(data))

        conn.close()

def start(addr, fname):
    thread = threading.Thread(group=None, target=listen, name='Action-Listener', args=(addr,fname))
    thread.start()
    return thread

if __name__ == '__main__':
    # Threaded option to enable multiple instances for multiple user access support
    addr = sys.argv[1]
    port = int(sys.argv[2])
    fname = sys.argv[3]

    print(addr, port, fname)

    start((addr, port), fname)
